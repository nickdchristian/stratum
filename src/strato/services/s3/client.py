import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar, cast

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def safe_aws_call(default: Any, safe_error_codes: list[str] | None = None) -> Callable:
    """
    Decorator to standardize AWS ClientError handling.
    """
    if safe_error_codes is None:
        safe_error_codes = []

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")

                if error_code in safe_error_codes:
                    return cast(T, default)

                resource = kwargs.get("Bucket", "unknown resource")
                logger.warning(
                    "AWS Error in %s for %s: %s - %s",
                    func.__name__,
                    resource,
                    error_code,
                    e,
                )
                return cast(T, default)
            except Exception as e:
                logger.error("Unexpected error in %s: %s", func.__name__, e)
                return cast(T, default)

        return wrapper

    return decorator


class S3Client:
    """
    Wrapper for Boto3 S3 interactions.
    """

    CRITICAL_LOG_PRINCIPALS = {
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "delivery.logs.amazonaws.com",
    }

    STORAGE_METRIC_MAP = {
        "Standard": "StandardStorage",
        "Intelligent-Tiering": "IntelligentTieringIAStorage",
        "Standard-IA": "StandardIAStorage",
        "OneZone-IA": "OneZoneIAStorage",
        "Glacier": "GlacierStorage",
        "Glacier-Deep-Archive": "GlacierDeepArchiveStorage",
        "RRS": "ReducedRedundancyStorage",
    }

    def __init__(self, session: boto3.Session | None = None):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self._client = self.session.client("s3", config=self.retry_config)
        self._region_cache: dict[str, str] = {}

    def _get_cw_client(self, bucket_name: str) -> Any:
        region = self.get_bucket_region(bucket_name)
        if not region:
            raise ValueError(f"Could not determine region for bucket: {bucket_name}")

        return self.session.client(
            "cloudwatch", region_name=region, config=self.retry_config
        )

    def list_buckets(self) -> list[dict[str, Any]]:
        try:
            paginator = self._client.get_paginator("list_buckets")
            buckets = []
            for page in paginator.paginate():
                buckets.extend(page.get("Buckets", []))
            return buckets
        except ClientError as e:
            logger.error("Critical: Failed to list buckets. %s", e)
            raise

    def get_bucket_region(self, bucket_name: str) -> str | None:
        if bucket_name in self._region_cache:
            return self._region_cache[bucket_name]

        try:
            response = self._client.get_bucket_location(Bucket=bucket_name)
            region = response.get("LocationConstraint") or "us-east-1"
            self._region_cache[bucket_name] = region
            return region
        except ClientError:
            return None

    @safe_aws_call(default=False)
    def get_public_access_status(self, bucket_name: str) -> bool:
        response = self._client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
        return all(
            [
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ]
        )

    @safe_aws_call(
        default={"Access": "Unknown", "SSL_Enforced": False, "Log_Sources": []},
        safe_error_codes=["NoSuchBucketPolicy"],
    )
    def get_bucket_policy(self, bucket_name: str) -> dict[str, Any]:
        assessment = {
            "Access": "Private",
            "SSL_Enforced": False,
            "Log_Sources": [],
        }

        response = self._client.get_bucket_policy(Bucket=bucket_name)
        policy_json = response.get("Policy", "{}")
        policy = json.loads(policy_json)

        for statement in policy.get("Statement", []):
            self._analyze_policy_statement(statement, assessment)

        return assessment

    def _analyze_policy_statement(self, statement: dict, assessment: dict) -> None:
        effect = statement.get("Effect")
        condition = statement.get("Condition", {})
        principal = statement.get("Principal")

        if effect == "Deny":
            bool_cond = condition.get("Bool", {})
            if str(bool_cond.get("aws:SecureTransport")).lower() == "false":
                assessment["SSL_Enforced"] = True

        if effect == "Allow":
            self._check_allow_statement(principal, condition, assessment)

    def _check_allow_statement(
        self, principal: Any, condition: dict, assessment: dict
    ) -> None:
        is_wildcard = principal == "*"
        is_aws_wildcard = isinstance(principal, dict) and principal.get("AWS") == "*"

        if is_wildcard or is_aws_wildcard:
            if condition:
                if assessment["Access"] != "Public":
                    assessment["Access"] = "Potentially Public"
            else:
                assessment["Access"] = "Public"

        if isinstance(principal, dict):
            service = principal.get("Service")
            services = [service] if isinstance(service, str) else (service or [])
            for svc in services:
                if (
                    svc in self.CRITICAL_LOG_PRINCIPALS
                    and svc not in assessment["Log_Sources"]
                ):
                    assessment["Log_Sources"].append(svc)

    @safe_aws_call(
        default={
            "SSEAlgorithm": None,
            "SSECBlocked": False,
            "BucketKeyEnabled": False,
            "KMSMasterKeyID": None,
        },
        safe_error_codes=["ServerSideEncryptionConfigurationNotFoundError"],
    )
    def get_encryption_status(self, bucket_name: str) -> dict[str, Any]:
        response = self._client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

        if not rules:
            return {
                "SSEAlgorithm": None,
                "SSECBlocked": False,
                "BucketKeyEnabled": False,
                "KMSMasterKeyID": None,
            }

        rule = rules[0]
        config = rule.get("ApplyServerSideEncryptionByDefault", {})

        return {
            "SSEAlgorithm": config.get("SSEAlgorithm"),
            "KMSMasterKeyID": config.get("KMSMasterKeyID"),
            "BucketKeyEnabled": config.get("BucketKeyEnabled", False),
            "SSECBlocked": "SSE-C" in rule.get("BlockedEncryptionTypes", []),
        }

    @safe_aws_call(default={"Status": "Enabled", "Ownership": "Unknown"})
    def get_acl_status(self, bucket_name: str) -> dict[str, str]:
        """
        Returns a dict with 'Status' (Enabled/Disabled) and the raw 'Ownership' type.
        """
        response = self._client.get_bucket_ownership_controls(Bucket=bucket_name)
        rules = response.get("OwnershipControls", {}).get("Rules", [])

        if not rules:
            return {"Status": "Enabled", "Ownership": "ObjectWriter"}

        ownership = rules[0].get("ObjectOwnership", "Unknown")
        status = "Disabled" if ownership == "BucketOwnerEnforced" else "Enabled"

        return {"Status": status, "Ownership": ownership}

    @safe_aws_call(default=False)
    def is_log_target(self, bucket_name: str) -> bool:
        log_delivery_uri = "http://acs.amazonaws.com/groups/s3/LogDelivery"
        cf_canonical_user = (
            "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
        )

        acl = self._client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") == log_delivery_uri:
                return True
            if (
                grantee.get("Type") == "CanonicalUser"
                and grantee.get("ID") == cf_canonical_user
            ):
                return True
        return False

    @safe_aws_call(default={"Status": None, "MFADelete": False})
    def get_versioning_status(self, bucket_name: str) -> dict[str, Any]:
        response = self._client.get_bucket_versioning(Bucket=bucket_name)
        return {
            "Status": response.get("Status", "Suspended"),
            "MFADelete": response.get("MFADelete") == "Enabled",
        }

    @safe_aws_call(
        default={
            "Status": False,
            "Mode": None,
            "RetentionDays": None,
            "RetentionYears": None,
        },
        safe_error_codes=["ObjectLockConfigurationNotFoundError"],
    )
    def get_object_lock_details(self, bucket_name: str) -> dict[str, Any]:
        response = self._client.get_object_lock_configuration(Bucket=bucket_name)
        config = response.get("ObjectLockConfiguration", {})

        result = {
            "Status": config.get("ObjectLockEnabled") == "Enabled",
            "Mode": None,
            "RetentionDays": None,
            "RetentionYears": None,
        }

        rule = config.get("Rule", {}).get("DefaultRetention", {})
        if rule:
            result["Mode"] = rule.get("Mode")
            result["RetentionDays"] = rule.get("Days")
            result["RetentionYears"] = rule.get("Years")
        return result

    @safe_aws_call(default=False, safe_error_codes=["NoSuchWebsiteConfiguration"])
    def get_website_hosting_status(self, bucket_name: str) -> bool:
        self._client.get_bucket_website(Bucket=bucket_name)
        return True

    @safe_aws_call(default=None)
    def get_logging_status(self, bucket_name: str) -> str | None:
        response = self._client.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" in response:
            return response["LoggingEnabled"].get("TargetBucket")
        return None

    @safe_aws_call(default=False)
    def get_accelerate_configuration(self, bucket_name: str) -> str:
        response = self._client.get_bucket_accelerate_configuration(Bucket=bucket_name)
        return response.get("Status")

    @safe_aws_call(default={})
    def get_bucket_tags(self, bucket_name: str) -> dict[str, str]:
        response = self._client.get_bucket_tagging(Bucket=bucket_name)
        return {t["Key"]: t["Value"] for t in response.get("TagSet", [])}

    @safe_aws_call(default="BucketOwner")
    def get_request_payment(self, bucket_name: str) -> str:
        response = self._client.get_bucket_request_payment(Bucket=bucket_name)
        return response.get("Payer", "BucketOwner")

    @safe_aws_call(default=0)
    def get_cors_count(self, bucket_name: str) -> int:
        response = self._client.get_bucket_cors(Bucket=bucket_name)
        return len(response.get("CORSRules", []))

    @safe_aws_call(
        default=[], safe_error_codes=["ReplicationConfigurationNotFoundError"]
    )
    def get_replication_configuration(self, bucket_name: str) -> list[dict[str, Any]]:
        response = self._client.get_bucket_replication(Bucket=bucket_name)
        rules = response.get("ReplicationConfiguration", {}).get("Rules", [])

        results = []
        for rule in rules:
            dest = rule.get("Destination", {})
            metrics = dest.get("Metrics", {})
            results.append(
                {
                    "ID": rule.get("ID"),
                    "Status": rule.get("Status"),
                    "Priority": rule.get("Priority"),
                    "Scope": "Filter" if rule.get("Filter") else "All",
                    "DestinationBucket": dest.get("Bucket"),
                    "StorageClass": dest.get("StorageClass"),
                    "Owner": dest.get("Account"),
                    "TimeControls": bool(metrics.get("EventThreshold")),
                    "KMSEncrypted": bool(dest.get("EncryptionConfiguration")),
                    "ReplicaModSync": rule.get("SourceSelectionCriteria", {})
                    .get("ReplicaModifications", {})
                    .get("Status")
                    == "Enabled",
                }
            )
        return results

    def calculate_replication_cost_impact(
        self, source_region: str, replication_rules: list[dict]
    ) -> list[str]:
        if not replication_rules:
            return []

        impacts = set()
        for rule in replication_rules:
            if rule["Status"] != "Enabled":
                continue

            dest_arn = rule.get("DestinationBucket")
            if not dest_arn:
                continue

            dest_bucket = dest_arn.split(":")[-1]
            dest_region = self.get_bucket_region(dest_bucket)

            if not dest_region:
                impacts.add("Cross-Account")
            elif dest_region != source_region:
                impacts.add("Cross-Region")
            else:
                impacts.add("Same-Region")

        return list(impacts)

    @safe_aws_call(default=[], safe_error_codes=["NoSuchLifecycleConfiguration"])
    def get_lifecycle_configuration(self, bucket_name: str) -> list[dict[str, Any]]:
        response = self._client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = response.get("Rules", [])

        results = []
        for rule in rules:
            transitions = [t.get("StorageClass") for t in rule.get("Transitions", [])]
            results.append(
                {
                    "ID": rule.get("ID"),
                    "Status": rule.get("Status"),
                    "Prefix": rule.get("Prefix", ""),
                    "Transitions": transitions,
                    "Expiration": "Expiration" in rule,
                }
            )
        return results

    @safe_aws_call(default=[])
    def get_intelligent_tiering_configurations(self, bucket_name: str) -> list[str]:
        res = self._client.list_bucket_intelligent_tiering_configurations(
            Bucket=bucket_name
        )
        return [c.get("Id") for c in res.get("IntelligentTieringConfigurationList", [])]

    @safe_aws_call(default=0)
    def get_notification_configuration_count(self, bucket_name: str) -> int:
        res = self._client.get_bucket_notification_configuration(Bucket=bucket_name)
        keys = [
            "TopicConfigurations",
            "QueueConfigurations",
            "LambdaFunctionConfigurations",
        ]
        return sum(len(res.get(k, [])) for k in keys)

    @safe_aws_call(default=0)
    def get_inventory_configuration_count(self, bucket_name: str) -> int:
        res = self._client.list_bucket_inventory_configurations(Bucket=bucket_name)
        return len(res.get("InventoryConfigurationList", []))

    @safe_aws_call(default=0)
    def get_analytics_configuration_count(self, bucket_name: str) -> int:
        res = self._client.list_bucket_analytics_configurations(Bucket=bucket_name)
        return len(res.get("AnalyticsConfigurationList", []))

    @safe_aws_call(default=0)
    def get_metrics_configuration_count(self, bucket_name: str) -> int:
        res = self._client.list_bucket_metrics_configurations(Bucket=bucket_name)
        return len(res.get("MetricsConfigurationList", []))

    def get_bucket_metrics(self, bucket_name: str) -> dict[str, Any]:
        result = {
            "Storage": {
                k: {"Size": 0.0, "Count": 0} for k in self.STORAGE_METRIC_MAP.keys()
            },
            "Requests": {"All": 0, "Get": 0, "Put": 0},
            "TotalObjectCount": 0,
        }

        try:
            cw = self._get_cw_client(bucket_name)
        except (ValueError, ClientError):
            return result

        queries = self._build_metric_queries(bucket_name)

        try:
            response = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=datetime.now(UTC) - timedelta(days=4),
                EndTime=datetime.now(UTC),
            )
            self._parse_metric_results(response, result)
        except ClientError as e:
            logger.warning("Failed to fetch metrics for %s: %s", bucket_name, e)

        return result

    def _build_metric_queries(self, bucket_name: str) -> list[dict]:
        queries = []

        for label, storage_type in self.STORAGE_METRIC_MAP.items():
            safe_label = label.lower().replace("-", "_")
            queries.append(
                {
                    "Id": f"size_{safe_label}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/S3",
                            "MetricName": "BucketSizeBytes",
                            "Dimensions": [
                                {"Name": "BucketName", "Value": bucket_name},
                                {"Name": "StorageType", "Value": storage_type},
                            ],
                        },
                        "Period": 86400,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
            )

        queries.append(
            {
                "Id": "count_total",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/S3",
                        "MetricName": "NumberOfObjects",
                        "Dimensions": [
                            {"Name": "BucketName", "Value": bucket_name},
                            {"Name": "StorageType", "Value": "AllStorageTypes"},
                        ],
                    },
                    "Period": 86400,
                    "Stat": "Average",
                },
                "ReturnData": True,
            }
        )

        req_config = {"All": "AllRequests", "Get": "GetRequests", "Put": "PutRequests"}
        for key, metric in req_config.items():
            queries.append(
                {
                    "Id": f"req_{key.lower()}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/S3",
                            "MetricName": metric,
                            "Dimensions": [
                                {"Name": "BucketName", "Value": bucket_name},
                                {"Name": "FilterId", "Value": "EntireBucket"},
                            ],
                        },
                        "Period": 86400,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            )

        return queries

    def _parse_metric_results(self, response: dict, result: dict) -> None:
        id_map = {res["Id"]: res for res in response.get("MetricDataResults", [])}

        def get_latest_value(metric_data):
            if not metric_data or not metric_data.get("Values"):
                return 0
            data_points = sorted(
                zip(metric_data["Timestamps"], metric_data["Values"], strict=False),
                key=lambda x: x[0],
                reverse=True,
            )
            return data_points[0][1]

        for key in ["All", "Get", "Put"]:
            qid = f"req_{key.lower()}"
            if qid in id_map:
                result["Requests"][key] = int(get_latest_value(id_map[qid]))

        for label in self.STORAGE_METRIC_MAP.keys():
            safe_label = label.lower().replace("-", "_")
            size_qid = f"size_{safe_label}"

            if size_qid in id_map:
                bytes_val = get_latest_value(id_map[size_qid])
                result["Storage"][label]["Size"] = round(bytes_val / (1024**3), 4)

        if "count_total" in id_map:
            result["TotalObjectCount"] = int(get_latest_value(id_map["count_total"]))

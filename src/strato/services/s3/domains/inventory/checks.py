from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.s3.client import S3Client


class S3InventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


@dataclass
class S3InventoryResult(AuditResult):
    """
    Data container for S3 Inventory and Configuration details.
    """

    resource_arn: str
    resource_name: str
    region: str
    account_id: str

    creation_date: datetime | None = None
    encryption_type: str | None = None
    kms_master_key_id: str | None = None
    bucket_key_enabled: bool = False

    server_access_logging: str = "Disabled"
    block_all_public_access: bool = False
    bucket_ownership: str | None = None
    acl_status: str = "Disabled"
    has_bucket_policy: bool = False
    request_payer: str = "BucketOwner"
    cors_rules_count: int = 0
    static_website_hosting: str = "Disabled"

    transfer_acceleration: str = "Suspended"
    object_lock: str = "Disabled"
    object_lock_mode: str | None = None
    object_lock_retention: str | None = None
    intelligent_tiering_config: str = "None"
    mfa_delete: str = "Disabled"
    versioning_status: str = "Suspended"

    replication_status: str = "Disabled"
    replication_rule_name: str | None = None
    replication_destination: str | None = None
    replication_storage_class: str | None = None
    replication_kms_encrypted: bool = False
    replication_cost_impact: str | None = None
    lifecycle_status: str = "Disabled"
    lifecycle_rule_count: int = 0
    lifecycle_active_rule_id: str | None = None

    notification_configs: int = 0
    inventory_configs: int = 0
    analytics_configs: int = 0
    metric_configs: int = 0

    standard_size_gb: float = 0.0
    standard_ia_size_gb: float = 0.0
    rrs_size_gb: float = 0.0
    glacier_size_gb: float = 0.0
    deep_archive_size_gb: float = 0.0
    intelligent_tiering_size_gb: float = 0.0
    total_bucket_size_gb: float = 0.0

    glacier_object_count: int = 0
    deep_archive_object_count: int = 0
    total_object_count: int = 0

    all_requests_count: int = 0
    get_requests_count: int = 0
    put_requests_count: int = 0

    tags: dict[str, str] = field(default_factory=dict)
    check_type: str = S3InventoryScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the result to a dictionary, removing parent AuditResult fields
        that are not relevant to raw inventory data.
        """
        data = asdict(self)

        if self.creation_date:
            data["creation_date"] = self.creation_date.isoformat()

        keys_to_remove = ["findings", "status_score", "status"]
        for key in keys_to_remove:
            data.pop(key, None)

        return data


class S3InventoryScanner(BaseScanner[S3InventoryResult]):
    def __init__(
        self,
        check_type: str = S3InventoryScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = S3Client(session=self.session)

    @property
    def service_name(self) -> str:
        return f"S3 Inventory ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: dict) -> S3InventoryResult:
        """
        Compiles a comprehensive inventory of a single S3 bucket.
        """
        bucket_name = bucket_data["Name"]
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        creation_date = bucket_data.get("CreationDate")

        region = self.client.get_bucket_region(bucket_name)
        bucket_tags = self.client.get_bucket_tags(bucket_name)

        encryption_status = self.client.get_encryption_status(bucket_name)
        versioning_status = self.client.get_versioning_status(bucket_name)
        bucket_policy = self.client.get_bucket_policy(bucket_name)
        public_access_status = self.client.get_public_access_status(bucket_name)
        object_lock_details = self.client.get_object_lock_details(bucket_name)

        replication_rules = self.client.get_replication_configuration(bucket_name)
        lifecycle_rules = self.client.get_lifecycle_configuration(bucket_name)
        intelligent_tiering_configs = (
            self.client.get_intelligent_tiering_configurations(bucket_name)
        )

        bucket_metrics = self.client.get_bucket_metrics(bucket_name)
        storage_metrics = bucket_metrics["Storage"]
        request_metrics = bucket_metrics["Requests"]

        replication_info = self._extract_replication_info(replication_rules, region)
        lifecycle_info = self._extract_lifecycle_info(lifecycle_rules)

        total_bucket_size = sum(value["Size"] for value in storage_metrics.values())
        total_object_count = sum(value["Count"] for value in storage_metrics.values())

        return S3InventoryResult(
            account_id=self.account_id,
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            encryption_type=encryption_status.get("SSEAlgorithm"),
            kms_master_key_id=encryption_status.get("KMSMasterKeyID"),
            bucket_key_enabled=encryption_status.get("BucketKeyEnabled", False),
            block_all_public_access=public_access_status,
            has_bucket_policy=bucket_policy.get("Access") != "Error",
            bucket_ownership=self.client.get_acl_status(bucket_name)["Ownership"],
            acl_status=self.client.get_acl_status(bucket_name)["Status"],
            server_access_logging=self.client.get_logging_status(bucket_name),
            versioning_status=versioning_status.get("Status", "Suspended"),
            mfa_delete=versioning_status.get("MFADelete", "Disabled"),
            object_lock=object_lock_details.get("Status", "Disabled"),
            object_lock_mode=object_lock_details.get("Mode"),
            object_lock_retention=object_lock_details.get("Retention"),
            static_website_hosting="Enabled"
            if self.client.get_website_hosting_status(bucket_name)
            else "Disabled",
            transfer_acceleration=self.client.get_accelerate_configuration(bucket_name),
            request_payer=self.client.get_request_payment(bucket_name),
            cors_rules_count=self.client.get_cors_count(bucket_name),
            intelligent_tiering_config="Enabled"
            if intelligent_tiering_configs
            else "Disabled",
            **replication_info,
            **lifecycle_info,
            notification_configs=self.client.get_notification_configuration_count(
                bucket_name
            ),
            inventory_configs=self.client.get_inventory_configuration_count(
                bucket_name
            ),
            analytics_configs=self.client.get_analytics_configuration_count(
                bucket_name
            ),
            metric_configs=self.client.get_metrics_configuration_count(bucket_name),
            standard_size_gb=storage_metrics["Standard"]["Size"],
            standard_ia_size_gb=storage_metrics["Standard-IA"]["Size"],
            intelligent_tiering_size_gb=storage_metrics["Intelligent-Tiering"]["Size"],
            rrs_size_gb=storage_metrics["RRS"]["Size"],
            glacier_size_gb=storage_metrics["Glacier"]["Size"],
            deep_archive_size_gb=storage_metrics["Glacier-Deep-Archive"]["Size"],
            glacier_object_count=storage_metrics["Glacier"]["Count"],
            deep_archive_object_count=storage_metrics["Glacier-Deep-Archive"]["Count"],
            total_bucket_size_gb=round(total_bucket_size, 2),
            total_object_count=total_object_count,
            all_requests_count=request_metrics["All"],
            get_requests_count=request_metrics["Get"],
            put_requests_count=request_metrics["Put"],
            tags=bucket_tags,
            check_type=self.check_type,
        )

    def _extract_replication_info(
        self, rules: list[dict], region: str
    ) -> dict[str, Any]:
        """
        Helper to extract summary data from replication rules.
        """
        cost_impact = self.client.calculate_replication_cost_impact(region, rules)
        if cost_impact == "None":
            cost_impact = None

        if not rules:
            return {
                "replication_status": "Disabled",
                "replication_cost_impact": cost_impact,
            }

        rule = rules[0]
        return {
            "replication_status": rule.get("Status", "Unknown"),
            "replication_rule_name": rule.get("ID"),
            "replication_destination": rule.get("DestinationBucket"),
            "replication_storage_class": rule.get("StorageClass", "Standard"),
            "replication_kms_encrypted": rule.get("KMSEncrypted") == "Enabled",
            "replication_cost_impact": cost_impact,
        }

    @staticmethod
    def _extract_lifecycle_info(rules: list[dict]) -> dict[str, Any]:
        """
        Helper to extract summary data from lifecycle rules.
        """
        if not rules:
            return {
                "lifecycle_status": "Disabled",
                "lifecycle_rule_count": 0,
                "lifecycle_active_rule_id": None,
            }

        return {
            "lifecycle_status": "Enabled",
            "lifecycle_rule_count": len(rules),
            "lifecycle_active_rule_id": rules[0].get("ID"),
        }

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

                if error_code in [
                    "ResourceNotFoundException",
                    "InvalidParameterValueException",
                    "AccessDeniedException",
                ]:
                    return cast(T, default)

                logger.warning(f"AWS Error in {func.__name__}: {error_code}")
                return cast(T, default)
            except Exception:
                return cast(T, default)

        return wrapper

    return decorator


class LambdaClient:
    """
    Wrapper for Boto3 Lambda, CloudWatch, and Logs interactions.
    """

    def __init__(self, session: boto3.Session | None = None):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self._client = self.session.client("lambda", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)
        self._logs_client = self.session.client("logs", config=self.retry_config)

    def list_functions(self) -> list[dict[str, Any]]:
        """
        Pages through all Lambda functions in the region.
        """
        paginator = self._client.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
        return functions

    @safe_aws_call(default=(None, None))
    def get_function_url_details(
        self, function_name: str
    ) -> tuple[str | None, str | None]:
        """
        Retrieves URL and AuthType.
        """
        response = self._client.get_function_url_config(FunctionName=function_name)
        return response.get("FunctionUrl"), response.get("AuthType")

    @safe_aws_call(default=[])
    def get_function_aliases(self, function_name: str) -> list[str]:
        paginator = self._client.get_paginator("list_aliases")
        aliases = []
        for page in paginator.paginate(FunctionName=function_name):
            for alias in page.get("Aliases", []):
                aliases.append(alias.get("Name"))
        return aliases

    @safe_aws_call(default=[])
    def get_event_source_mappings(self, function_name: str) -> list[str]:
        paginator = self._client.get_paginator("list_event_source_mappings")
        mappings = []
        for page in paginator.paginate(FunctionName=function_name):
            for mapping in page.get("EventSourceMappings", []):
                mappings.append(mapping.get("EventSourceArn") or mapping.get("UUID"))
        return mappings

    @safe_aws_call(default={})
    def get_tags(self, resource_arn: str) -> dict[str, str]:
        response = self._client.list_tags(Resource=resource_arn)
        return response.get("Tags", {})

    @safe_aws_call(default=0)
    def get_log_retention(self, log_group_name: str) -> int:
        response = self._logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name, limit=1
        )
        groups = response.get("logGroups", [])
        if groups and groups[0]["logGroupName"] == log_group_name:
            return groups[0].get("retentionInDays", 0)
        return 0

    def get_metric_sum(
        self, metric_name: str, function_name: str, days: int = 14
    ) -> float:
        return (
            self._get_metric_stat("Sum", "AWS/Lambda", metric_name, function_name, days)
            or 0.0
        )

    def get_metric_max(
        self, metric_name: str, function_name: str, days: int = 14
    ) -> float:
        return (
            self._get_metric_stat(
                "Maximum", "AWS/Lambda", metric_name, function_name, days
            )
            or 0.0
        )

    def get_metric_avg(
        self, metric_name: str, function_name: str, days: int = 14
    ) -> float:
        return (
            self._get_metric_stat(
                "Average", "AWS/Lambda", metric_name, function_name, days
            )
            or 0.0
        )

    def get_lambda_insight_metric(
        self, metric_name: str, function_name: str, days: int = 14
    ) -> float | None:
        return self._get_metric_stat(
            "Maximum", "LambdaInsights", metric_name, function_name, days
        )

    def _get_metric_stat(
        self,
        stat: str,
        namespace: str,
        metric_name: str,
        function_name: str,
        days: int,
    ) -> float | None:
        try:
            dims = [{"Name": "FunctionName", "Value": function_name}]

            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dims,
                StartTime=datetime.now(UTC) - timedelta(days=days),
                EndTime=datetime.now(UTC),
                Period=86400 * days,
                Statistics=[stat],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return None
            return datapoints[0][stat]
        except ClientError:
            return None

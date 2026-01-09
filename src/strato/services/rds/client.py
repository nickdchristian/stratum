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

                if error_code not in ["AccessDeniedException", "InvalidParameter"]:
                    logger.warning(f"AWS Error in {func.__name__}: {error_code}")
                return cast(T, default)
            except Exception:
                return cast(T, default)

        return wrapper

    return decorator


class RDSClient:
    """
    Wrapper for Boto3 RDS and CloudWatch interactions.
    """

    def __init__(self, session: boto3.Session | None = None):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self._client = self.session.client("rds", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)

    def list_instances(self) -> list[dict[str, Any]]:
        """
        Pages through all RDS instances in the region.
        """
        paginator = self._client.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances

    def get_reserved_instances(self) -> list[dict[str, Any]]:
        """
        Pages through all Reserved RDS instances in the region.
        """
        paginator = self._client.get_paginator("describe_reserved_db_instances")
        ris = []
        for page in paginator.paginate():
            ris.extend(page.get("ReservedDBInstances", []))
        return ris

    @safe_aws_call(default=(0.0, 0.0))
    def get_cpu_utilization(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db_identifier, days
        )

    @safe_aws_call(default=(0.0, 0.0))
    def get_database_connections(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS",
            "DatabaseConnections",
            "DBInstanceIdentifier",
            db_identifier,
            days,
        )

    @safe_aws_call(default=(0.0, 0.0))
    def get_write_throughput(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "WriteThroughput", "DBInstanceIdentifier", db_identifier, days
        )

    @safe_aws_call(default=(0.0, 0.0))
    def get_read_throughput(
        self, db_identifier: str, days: int = 90
    ) -> tuple[float, float]:
        return self._get_metric_stats(
            "AWS/RDS", "ReadThroughput", "DBInstanceIdentifier", db_identifier, days
        )

    def _get_metric_stats(
        self,
        namespace: str,
        metric_name: str,
        dimension_name: str,
        dimension_value: str,
        days: int,
    ) -> tuple[float, float]:
        try:
            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
                StartTime=datetime.now(UTC) - timedelta(days=days),
                EndTime=datetime.now(UTC),
                Period=86400,
                Statistics=["Maximum", "Average"],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return 0.0, 0.0

            peak = max(d["Maximum"] for d in datapoints)
            mean = sum(d["Average"] for d in datapoints) / len(datapoints)
            return round(peak, 2), round(mean, 2)
        except ClientError:
            return 0.0, 0.0

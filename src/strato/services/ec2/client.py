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


class EC2Client:
    """
    Wrapper for Boto3 EC2, CloudWatch, and SSM interactions.
    """

    def __init__(self, session: boto3.Session | None = None):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self._client = self.session.client("ec2", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)
        self._ssm_client = self.session.client("ssm", config=self.retry_config)
        self._optimizer_enrolled = None

    def list_instances(self) -> list[dict[str, Any]]:
        """
        Pages through all EC2 instances in the region.
        """
        paginator = self._client.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances

    @safe_aws_call(default=[])
    def get_reserved_instances(self) -> list[dict[str, Any]]:
        """
        Retrieves active Reserved Instances.
        """
        response = self._client.describe_reserved_instances(
            Filters=[{"Name": "state", "Values": ["active", "retired"]}]
        )
        return response.get("ReservedInstances", [])

    @safe_aws_call(default={})
    def get_image_details(self, image_id: str) -> dict[str, Any]:
        """
        Retrieves basic metadata about the AMI.
        """
        if not image_id:
            return {}
        response = self._client.describe_images(ImageIds=[image_id])
        images = response.get("Images", [])
        if not images:
            return {}

        img = images[0]
        return {
            "Name": img.get("Name"),
            "OwnerAlias": img.get("ImageOwnerAlias"),
            "CreationDate": img.get("CreationDate"),
            "Description": img.get("Description"),
        }

    @safe_aws_call(default=False)
    def get_termination_protection(self, instance_id: str) -> bool:
        """
        Checks if API termination is disabled.
        """
        response = self._client.describe_instance_attribute(
            InstanceId=instance_id, Attribute="disableApiTermination"
        )
        return response.get("DisableApiTermination", {}).get("Value", False)

    @safe_aws_call(default={})
    def get_volume_details(self, volume_ids: list[str]) -> dict[str, dict]:
        """
        Retrieves encryption and size details for a list of EBS volumes.
        """
        if not volume_ids:
            return {}
        response = self._client.describe_volumes(VolumeIds=volume_ids)
        volumes = {}
        for vol in response.get("Volumes", []):
            volumes[vol["VolumeId"]] = {
                "Encrypted": vol.get("Encrypted", False),
                "Size": vol.get("Size"),
                "Type": vol.get("VolumeType"),
            }
        return volumes

    @safe_aws_call(default=False)
    def is_instance_managed(self, instance_id: str) -> bool:
        """
        Checks SSM to see if the instance is reporting as online/managed.
        """
        try:
            self._ssm_client.describe_instance_information(
                InstanceInformationFilterList=[
                    {"key": "InstanceIds", "valueSet": [instance_id]}
                ]
            )
            return True
        except ClientError:
            return False

    @safe_aws_call(default={"Inbound": [], "Outbound": []})
    def get_security_group_rules(self, group_ids: list[str]) -> dict[str, list[str]]:
        """
        Analyzes security groups to return a summary of open ports.
        """
        if not group_ids:
            return {"Inbound": [], "Outbound": []}

        response = self._client.describe_security_groups(GroupIds=group_ids)
        inbound = set()
        outbound = set()

        for sg in response.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                p_range = "All"
                if perm.get("FromPort") == perm.get("ToPort"):
                    p_range = str(perm.get("FromPort"))
                elif perm.get("FromPort"):
                    p_range = f"{perm['FromPort']}-{perm['ToPort']}"
                inbound.add(p_range)

            for perm in sg.get("IpPermissionsEgress", []):
                p_range = "All"
                if perm.get("FromPort"):
                    p_range = str(perm.get("FromPort"))
                outbound.add(p_range)

        return {"Inbound": list(inbound), "Outbound": list(outbound)}

    def check_optimizer_enrollment(self) -> str:
        """
        Checks if Compute Optimizer is actually enabled for this account.
        """
        if self._optimizer_enrolled is not None:
            return self._optimizer_enrolled

        try:
            opt_client = self.session.client(
                "compute-optimizer", config=self.retry_config
            )
            resp = opt_client.get_enrollment_status()
            status = resp.get("status", "Inactive")
            self._optimizer_enrolled = "Active" if status == "Active" else "Disabled"
        except (ClientError, Exception):
            self._optimizer_enrolled = "Unavailable"

        return self._optimizer_enrolled

    def get_memory_utilization(self, instance_id: str, days: int = 14) -> float | None:
        """
        Returns None if agent is missing or metrics unavailable.
        """
        try:
            metrics_check = self._cw_client.list_metrics(
                Namespace="CWAgent",
                MetricName="mem_used_percent",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            )
            if not metrics_check.get("Metrics"):
                return None
        except ClientError:
            return None

        val = self._get_metric_max(
            namespace="CWAgent",
            metric_name="mem_used_percent",
            dimension_name="InstanceId",
            dimension_value=instance_id,
            days=days,
        )
        return round(val, 2) if val is not None else None

    def get_cpu_utilization(self, instance_id: str, days: int = 14) -> float:
        """
        Returns the maximum CPU utilization percentage over the lookback period.
        """
        val = self._get_metric_max(
            "AWS/EC2", "CPUUtilization", "InstanceId", instance_id, days
        )
        return round(val, 2) if val is not None else 0.0

    def get_network_utilization(self, instance_id: str, days: int = 14) -> float:
        """
        Returns the average network in+out bytes over the lookback period.
        """
        in_bytes = (
            self._get_metric_avg(
                "AWS/EC2", "NetworkIn", "InstanceId", instance_id, days
            )
            or 0.0
        )
        out_bytes = (
            self._get_metric_avg(
                "AWS/EC2", "NetworkOut", "InstanceId", instance_id, days
            )
            or 0.0
        )
        return round((in_bytes + out_bytes) / 2, 2)

    def _get_metric_max(
        self,
        namespace: str,
        metric_name: str,
        dimension_name: str,
        dimension_value: str,
        days: int,
    ) -> float | None:
        try:
            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
                StartTime=datetime.now(UTC) - timedelta(days=days),
                EndTime=datetime.now(UTC),
                Period=86400,
                Statistics=["Maximum"],
            )
            datapoints = response.get("Datapoints", [])
            return max(d["Maximum"] for d in datapoints) if datapoints else None
        except ClientError:
            return None

    def _get_metric_avg(
        self,
        namespace: str,
        metric_name: str,
        dimension_name: str,
        dimension_value: str,
        days: int,
    ) -> float | None:
        try:
            response = self._cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
                StartTime=datetime.now(UTC) - timedelta(days=days),
                EndTime=datetime.now(UTC),
                Period=86400,
                Statistics=["Average"],
            )
            datapoints = response.get("Datapoints", [])
            if not datapoints:
                return None
            return sum(d["Average"] for d in datapoints) / len(datapoints)
        except ClientError:
            return None

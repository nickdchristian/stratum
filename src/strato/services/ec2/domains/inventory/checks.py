from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.ec2.client import EC2Client


class EC2InventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


@dataclass
class EC2InventoryResult(AuditResult):
    """
    Data container for EC2 Inventory and Configuration details.
    """

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""
    region: str = ""
    account_id: str = "Unknown"

    instance_type: str | None = None
    state: str | None = None
    availability_zone: str | None = None
    private_ip: str | None = None
    private_ip6: str | None = None
    public_ip4: str | None = None
    elastic_ip: str | None = None
    launch_time: datetime | None = None
    platform: str | None = None
    architecture: str | None = None
    instance_lifecycle: str = "on-demand"
    managed: bool = False

    image_id: str | None = None
    ami_name: str | None = None
    ami_owner_alias: str | None = None
    ami_create_date: str | None = None

    vpc_id: str | None = None
    subnet_id: str | None = None
    root_device_type: str | None = None

    highest_cpu_14_days: float = 0.0
    highest_cpu_90_days: float = 0.0
    highest_memory_14_days: float | None = None
    highest_memory_90_days: float | None = None
    network_util_14_days: float = 0.0
    network_util_90_days: float = 0.0
    rightsizing_recommendation: str | None = None

    attached_volumes: int = 0
    attached_volume_encryption_status: str = "Unknown"
    delete_on_termination_status: bool = False

    security_groups_count: int = 0
    security_group_list: list[str] = field(default_factory=list)
    security_group_inbound_ports: list[str] = field(default_factory=list)
    security_group_outbound_ports: list[str] = field(default_factory=list)
    iam_instance_profile: str | None = None
    monitoring_enabled: str = "basic"
    termination_protection: bool = False

    tags: dict[str, str] = field(default_factory=dict)
    check_type: str = EC2InventoryScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the result to a dictionary.
        """
        data = asdict(self)
        if self.launch_time:
            data["launch_time"] = self.launch_time.isoformat()

        keys_to_remove = ["findings", "status_score", "status"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class EC2InventoryScanner(BaseScanner[EC2InventoryResult]):
    def __init__(
        self,
        check_type: str = EC2InventoryScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = EC2Client(session=self.session)
        self.optimizer_status = self.client.check_optimizer_enrollment()

    @property
    def service_name(self) -> str:
        return f"EC2 Inventory ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_instances()

    def analyze_resource(self, instance_data: dict) -> EC2InventoryResult:
        """
        Compiles a comprehensive inventory of a single EC2 instance.
        """
        instance_id = instance_data["InstanceId"]
        name_tag = next(
            (t["Value"] for t in instance_data.get("Tags", []) if t["Key"] == "Name"),
            instance_id,
        )
        tags = {t["Key"]: t["Value"] for t in instance_data.get("Tags", [])}

        mappings = instance_data.get("BlockDeviceMappings", [])
        volume_ids = [m["Ebs"]["VolumeId"] for m in mappings if "Ebs" in m]
        vol_details = self.client.get_volume_details(volume_ids)
        encryption_statuses = [v["Encrypted"] for v in vol_details.values()]

        enc_str = (
            "Encrypted"
            if all(encryption_statuses) and encryption_statuses
            else "Unencrypted"
            if not any(encryption_statuses)
            else "Mixed"
        )

        img_info = self.client.get_image_details(instance_data.get("ImageId"))

        cpu_14 = self.client.get_cpu_utilization(instance_id, days=14)
        cpu_90 = self.client.get_cpu_utilization(instance_id, days=90)
        mem_14 = self.client.get_memory_utilization(instance_id, days=14)
        mem_90 = self.client.get_memory_utilization(instance_id, days=90)
        net_14 = self.client.get_network_utilization(instance_id, days=14)
        net_90 = self.client.get_network_utilization(instance_id, days=90)

        rightsizing = None
        if self.optimizer_status != "Active":
            rightsizing = f"Optimizer{self.optimizer_status}"

        sgs = instance_data.get("SecurityGroups", [])
        sg_ids = [sg["GroupId"] for sg in sgs]
        sg_rules = self.client.get_security_group_rules(sg_ids)

        iam_profile = instance_data.get("IamInstanceProfile", {}).get("Arn")
        if iam_profile:
            iam_profile = iam_profile.split("/")[-1]

        return EC2InventoryResult(
            account_id=self.account_id,
            resource_id=instance_id,
            resource_name=name_tag,
            region=instance_data.get("Placement", {}).get("AvailabilityZone")[:-1],
            instance_type=instance_data.get("InstanceType"),
            state=instance_data.get("State", {}).get("Name"),
            availability_zone=instance_data.get("Placement", {}).get(
                "AvailabilityZone"
            ),
            private_ip=instance_data.get("PrivateIpAddress"),
            public_ip4=instance_data.get("PublicIpAddress"),
            launch_time=instance_data.get("LaunchTime"),
            platform=instance_data.get("Platform", "linux"),
            architecture=instance_data.get("Architecture"),
            instance_lifecycle=instance_data.get("InstanceLifecycle", "on-demand"),
            managed=self.client.is_instance_managed(instance_id),
            image_id=instance_data.get("ImageId"),
            ami_name=img_info.get("Name"),
            ami_owner_alias=img_info.get("OwnerAlias"),
            ami_create_date=img_info.get("CreationDate"),
            vpc_id=instance_data.get("VpcId"),
            subnet_id=instance_data.get("SubnetId"),
            root_device_type=instance_data.get("RootDeviceType"),
            highest_cpu_14_days=cpu_14,
            highest_cpu_90_days=cpu_90,
            highest_memory_14_days=mem_14,
            highest_memory_90_days=mem_90,
            network_util_14_days=net_14,
            network_util_90_days=net_90,
            rightsizing_recommendation=rightsizing,
            attached_volumes=len(volume_ids),
            attached_volume_encryption_status=enc_str,
            delete_on_termination_status=False,
            security_groups_count=len(sgs),
            security_group_list=sg_ids,
            security_group_inbound_ports=sg_rules["Inbound"],
            security_group_outbound_ports=sg_rules["Outbound"],
            iam_instance_profile=iam_profile,
            monitoring_enabled=instance_data.get("Monitoring", {}).get("State"),
            termination_protection=self.client.get_termination_protection(instance_id),
            tags=tags,
            check_type=self.check_type,
        )

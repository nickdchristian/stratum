from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.rds.client import RDSClient


class RDSInventoryScanType(StrEnum):
    ALL = auto()
    INVENTORY = auto()


@dataclass
class RDSInventoryResult(AuditResult):
    """
    Data container for RDS Inventory and Configuration details.
    """

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""
    region: str = ""
    account_id: str = "Unknown"

    db_identifier: str = ""
    db_cluster_identifier: str = ""
    status: str = ""
    rds_extended_support: str = "Unknown"
    engine: str = ""
    engine_version: str = ""
    availability_zone: str = ""
    size: str = ""
    vpc: str = ""
    port: int = 0
    security_group_ids: list[str] = field(default_factory=list)
    publicly_accessible: bool = False
    multi_az: bool = False
    storage_type: str = ""
    provisioned_iops: int = 0
    storage_throughput: int = 0

    iam_auth_enabled: bool = False
    ca_certificate_identifier: str = ""
    parameter_groups: list[str] = field(default_factory=list)
    option_groups: list[str] = field(default_factory=list)
    enabled_cloudwatch_logs_exports: list[str] = field(default_factory=list)

    peak_active_session_count_90_days: float = 0.0
    mean_active_session_count_90_days: float = 0.0
    peak_active_transactions_count_90_days: float = 0.0
    mean_active_transactions_count_90_days: float = 0.0
    peak_commit_throughput_90_days: float = 0.0
    mean_commit_throughput_90_days: float = 0.0

    peak_cpu_utilization_90_days: float = 0.0
    mean_cpu_utilization_90_days: float = 0.0

    peak_database_connections_90_days: float = 0.0
    mean_database_connections_90_days: float = 0.0

    peak_read_throughput_90_days: float = 0.0
    mean_read_throughput_90_days: float = 0.0
    peak_write_throughput_90_days: float = 0.0
    mean_write_throughput_90_days: float = 0.0

    allocated_storage: int = 0
    max_allocated_storage: int = 0
    storage_encrypted: bool = False
    backup_retention_period: int = 0
    preferred_backup_window: str = ""
    preferred_maintenance_window: str = ""
    auto_minor_version_upgrade: bool = False
    deletion_protection: bool = False
    performance_insights_enabled: bool = False
    monitoring_interval: int = 0
    enhanced_monitoring_resource_arn: str = ""
    license_model: str = ""

    monthly_cost_estimate: str = ""
    reserved_instance_coverage: str = ""
    rightsizing_recommendation: str = ""
    utilization_score: str = ""
    cost_optimization_opportunity: str = ""

    tags: dict[str, str] = field(default_factory=dict)
    check_type: str = RDSInventoryScanType.ALL

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = ["findings", "status_score", "status"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class RDSInventoryScanner(BaseScanner[RDSInventoryResult]):
    def __init__(
        self,
        check_type: str = RDSInventoryScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = RDSClient(session=self.session)

    @property
    def service_name(self) -> str:
        return f"RDS Inventory ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_instances()

    def analyze_resource(self, resource_data: dict) -> RDSInventoryResult:
        db_id = resource_data.get("DBInstanceIdentifier", "")
        arn = resource_data.get("DBInstanceArn", "")
        tags = {t["Key"]: t["Value"] for t in resource_data.get("TagList", [])}

        cpu_peak, cpu_mean = self.client.get_cpu_utilization(db_id)
        conn_peak, conn_mean = self.client.get_database_connections(db_id)
        write_peak, write_mean = self.client.get_write_throughput(db_id)
        read_peak, read_mean = self.client.get_read_throughput(db_id)

        az = resource_data.get("AvailabilityZone", "")
        sg_ids = [
            sg["VpcSecurityGroupId"]
            for sg in resource_data.get("VpcSecurityGroups", [])
        ]
        param_groups = [
            pg["DBParameterGroupName"]
            for pg in resource_data.get("DBParameterGroups", [])
        ]

        endpoint = resource_data.get("Endpoint", {})
        port = endpoint.get("Port", 0)

        log_exports = resource_data.get("EnabledCloudwatchLogsExports", [])
        option_groups = [
            og["OptionGroupName"]
            for og in resource_data.get("OptionGroupMemberships", [])
        ]

        return RDSInventoryResult(
            account_id=self.account_id,
            resource_id=db_id,
            resource_name=db_id,
            resource_arn=arn,
            region=az[:-1] if az else "",
            db_identifier=db_id,
            db_cluster_identifier=resource_data.get("DBClusterIdentifier", ""),
            status=resource_data.get("DBInstanceStatus", "unknown"),
            rds_extended_support="Unknown",
            engine=resource_data.get("Engine", ""),
            engine_version=resource_data.get("EngineVersion", ""),
            availability_zone=az,
            size=resource_data.get("DBInstanceClass", ""),
            vpc=resource_data.get("DBSubnetGroup", {}).get("VpcId", ""),
            port=port,
            security_group_ids=sg_ids,
            publicly_accessible=resource_data.get("PubliclyAccessible", False),
            multi_az=resource_data.get("MultiAZ", False),
            storage_type=resource_data.get("StorageType", ""),
            provisioned_iops=resource_data.get("Iops", 0),
            storage_throughput=resource_data.get("StorageThroughput", 0),
            iam_auth_enabled=resource_data.get(
                "IAMDatabaseAuthenticationEnabled", False
            ),
            ca_certificate_identifier=resource_data.get("CACertificateIdentifier", ""),
            parameter_groups=param_groups,
            option_groups=option_groups,
            enabled_cloudwatch_logs_exports=log_exports,
            peak_cpu_utilization_90_days=cpu_peak,
            mean_cpu_utilization_90_days=cpu_mean,
            peak_database_connections_90_days=conn_peak,
            mean_database_connections_90_days=conn_mean,
            peak_read_throughput_90_days=read_peak,
            mean_read_throughput_90_days=read_mean,
            peak_write_throughput_90_days=write_peak,
            mean_write_throughput_90_days=write_mean,
            allocated_storage=resource_data.get("AllocatedStorage", 0),
            max_allocated_storage=resource_data.get("MaxAllocatedStorage", 0),
            storage_encrypted=resource_data.get("StorageEncrypted", False),
            backup_retention_period=resource_data.get("BackupRetentionPeriod", 0),
            preferred_backup_window=resource_data.get("PreferredBackupWindow", ""),
            preferred_maintenance_window=resource_data.get(
                "PreferredMaintenanceWindow", ""
            ),
            auto_minor_version_upgrade=resource_data.get(
                "AutoMinorVersionUpgrade", False
            ),
            deletion_protection=resource_data.get("DeletionProtection", False),
            performance_insights_enabled=resource_data.get(
                "PerformanceInsightsEnabled", False
            ),
            monitoring_interval=resource_data.get("MonitoringInterval", 0),
            enhanced_monitoring_resource_arn=resource_data.get(
                "EnhancedMonitoringResourceArn", ""
            ),
            license_model=resource_data.get("LicenseModel", ""),
            tags=tags,
            check_type=self.check_type,
        )

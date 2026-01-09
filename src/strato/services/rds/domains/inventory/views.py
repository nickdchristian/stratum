from typing import Any

from strato.services.rds.domains.inventory.checks import RDSInventoryResult


class RDSInventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "account_id",
            "region",
            "db_identifier",
            "db_cluster_identifier",
            "status",
            "tags",
            "rds_extended_support",
            "engine",
            "engine_version",
            "availability_zone",
            "size",
            "publicly_accessible",
            "vpc",
            "port",
            "security_group_ids",
            "multi-az",
            "storage_type",
            "allocated_storage",
            "max_allocated_storage",
            "storage_encrypted",
            "provisioned_iops",
            "storage_throughput",
            "iam_auth_enabled",
            "ca_certificate_identifier",
            "parameter_groups",
            "option_groups",
            "enabled_cloudwatch_logs_exports",
            "peak_active_session_count_90_days",
            "mean_active_session_count_90_days",
            "peak_active_transactions_count_90_days",
            "mean_active_transactions_count_90_days",
            "peak_commit_throughput_90_days",
            "mean_commit_throughput_90_days",
            "peak_cpu_utilization_90_days",
            "mean_cpu_utilization_90_days",
            "peak_database_connections_90_days",
            "mean_database_connections_90_days",
            "peak_read_throughput_90_days",
            "mean_read_throughput_90_days",
            "peak_write_throughput_90_days",
            "mean_write_throughput_90_days",
            "backup_retention_period",
            "preferred_backup_window",
            "preferred_maintenance_window",
            "auto_minor_version_upgrade",
            "deletion_protection",
            "performance_insights_enabled",
            "monitoring_interval",
            "enhanced_monitoring_resource_arn",
            "license_model",
            "monthly_cost_estimate",
            "reserved_instance_coverage",
            "rightsizing_recommendation",
            "utilization_score",
            "cost_optimization_opportunity",
        ]

    @classmethod
    def format_row(cls, result: RDSInventoryResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: RDSInventoryResult) -> list[str]:
        tags_string = "; ".join(f"{key}={value}" for key, value in result.tags.items())

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return ";".join(str(x) for x in val)
            return str(val)

        return [
            result.account_id,
            result.region,
            result.db_identifier,
            result.db_cluster_identifier,
            result.status,
            tags_string,
            fmt(result.rds_extended_support),
            fmt(result.engine),
            fmt(result.engine_version),
            fmt(result.availability_zone),
            fmt(result.size),
            fmt(result.publicly_accessible),
            fmt(result.vpc),
            fmt(result.port),
            fmt(result.security_group_ids),
            fmt(result.multi_az),
            fmt(result.storage_type),
            fmt(result.allocated_storage),
            fmt(result.max_allocated_storage),
            fmt(result.storage_encrypted),
            fmt(result.provisioned_iops),
            fmt(result.storage_throughput),
            fmt(result.iam_auth_enabled),
            fmt(result.ca_certificate_identifier),
            fmt(result.parameter_groups),
            fmt(result.option_groups),
            fmt(result.enabled_cloudwatch_logs_exports),
            fmt(result.peak_active_session_count_90_days),
            fmt(result.mean_active_session_count_90_days),
            fmt(result.peak_active_transactions_count_90_days),
            fmt(result.mean_active_transactions_count_90_days),
            fmt(result.peak_commit_throughput_90_days),
            fmt(result.mean_commit_throughput_90_days),
            fmt(result.peak_cpu_utilization_90_days),
            fmt(result.mean_cpu_utilization_90_days),
            fmt(result.peak_database_connections_90_days),
            fmt(result.mean_database_connections_90_days),
            fmt(result.peak_read_throughput_90_days),
            fmt(result.mean_read_throughput_90_days),
            fmt(result.peak_write_throughput_90_days),
            fmt(result.mean_write_throughput_90_days),
            fmt(result.backup_retention_period),
            fmt(result.preferred_backup_window),
            fmt(result.preferred_maintenance_window),
            fmt(result.auto_minor_version_upgrade),
            fmt(result.deletion_protection),
            fmt(result.performance_insights_enabled),
            fmt(result.monitoring_interval),
            fmt(result.enhanced_monitoring_resource_arn),
            fmt(result.license_model),
            fmt(result.monthly_cost_estimate),
            fmt(result.reserved_instance_coverage),
            fmt(result.rightsizing_recommendation),
            fmt(result.utilization_score),
            fmt(result.cost_optimization_opportunity),
        ]

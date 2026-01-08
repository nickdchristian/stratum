import json
from typing import Any

from strato.core.presenter import GenericView
from strato.services.awslambda.domains.inventory.checks import LambdaInventoryResult


class LambdaInventoryView(GenericView):
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return [
            "region",
            "account_id",
            "function_name",
            "function_aliases",
            "function_arn",
            "function_description",
            "function_url",
            "function_url_auth_type",
            "function_architecture",
            "runtime",
            "code_size",
            "memory_size",
            "last_modified",
            "architecture",
            "environment_variables",
            "vpc_config_vpcid",
            "vpc_config_subnetid",
            "timeout",
            "provisioned_concurrency_config",
            "reserved_concurrency_limit",
            "billing_duration_ms",
            "estimated_monthly_cost",
            "dead_letter_queue_config",
            "cold_start_count",
            "warm_start_count",
            "average_duration_ms",
            "p95_duration_ms",
            "throttle_count",
            "concurrent_executions_peak",
            "concurrent_executions_average",
            "memory_utilization_percentage",
            "cpu_utilization_percentage",
            "network_bytes_in",
            "network_bytes_out",
            "storage_bytes_used",
            "kms_key_arn",
            "execution_role_arn",
            "layers",
            "signing_profile_version_arn",
            "code_signing_config_arn",
            "event_source_mappings",
            "destinations_on_success",
            "destinations_on_failure",
            "file_system_configs",
            "image_config_entry_point",
            "package_type",
            "tracing_config_mode",
            "log_retention_days",
            "insights_enabled",
            "custom_metrics_count",
            "creation_date",
            "last_invocation_date",
            "version_count",
            "state",
            "state_reason",
            "invocation_count",
            "duration",
            "error_count",
            "success_percentage",
            "ephemeral_storage",
            "recursive_loop",
            "triggers",
            "tags",
        ]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return cls.get_headers(check_type)

    @classmethod
    def format_csv_row(cls, result: LambdaInventoryResult) -> list[str]:
        def fmt(val: Any) -> str:
            """
            Serializes lists/dicts to valid JSON strings for robustness.
            """
            if val is None:
                return ""
            if isinstance(val, (list, dict)):
                return json.dumps(val)
            return str(val)

        def fmt_tags(tags: dict[str, str] | None) -> str:
            """
            Formats tags as 'Key=Value; Key2=Value2' for CSV readability.
            """
            if not tags:
                return ""
            # Sort keys for consistent output
            return "; ".join(f"{k}={v}" for k, v in sorted(tags.items()))

        return [
            fmt(result.region),
            fmt(result.account_id),
            fmt(result.resource_name),
            fmt(result.function_aliases),
            fmt(result.resource_arn),
            fmt(result.function_description),
            fmt(result.function_url),
            fmt(result.function_url_auth_type),
            fmt(result.function_architecture),
            fmt(result.runtime),
            fmt(result.code_size),
            fmt(result.memory_size),
            fmt(result.last_modified),
            fmt(result.architecture),
            fmt(result.environment_variables),
            fmt(result.vpc_config_vpcid),
            fmt(result.vpc_config_subnetid),
            fmt(result.timeout),
            fmt(result.provisioned_concurrency_config),
            fmt(result.reserved_concurrency_limit),
            fmt(result.billing_duration_ms),
            fmt(result.estimated_monthly_cost),
            fmt(result.dead_letter_queue_config),
            fmt(result.cold_start_count),
            fmt(result.warm_start_count),
            fmt(result.average_duration_ms),
            fmt(result.p95_duration_ms),
            fmt(result.throttle_count),
            fmt(result.concurrent_executions_peak),
            fmt(result.concurrent_executions_average),
            fmt(result.memory_utilization_percentage),
            fmt(result.cpu_utilization_percentage),
            fmt(result.network_bytes_in),
            fmt(result.network_bytes_out),
            fmt(result.storage_bytes_used),
            fmt(result.kms_key_arn),
            fmt(result.execution_role_arn),
            fmt(result.layers),
            fmt(result.signing_profile_version_arn),
            fmt(result.code_signing_config_arn),
            fmt(result.event_source_mappings),
            fmt(result.destinations_on_success),
            fmt(result.destinations_on_failure),
            fmt(result.file_system_configs),
            fmt(result.image_config_entry_point),
            fmt(result.package_type),
            fmt(result.tracing_config_mode),
            fmt(result.log_retention_days),
            fmt(result.insights_enabled),
            fmt(result.custom_metrics_count),
            fmt(result.creation_date),
            fmt(result.last_invocation_date),
            fmt(result.version_count),
            fmt(result.state),
            fmt(result.state_reason),
            fmt(result.invocation_count),
            fmt(result.duration),
            fmt(result.error_count),
            fmt(result.success_percentage),
            fmt(result.ephemeral_storage),
            fmt(result.recursive_loop),
            fmt(result.triggers),
            fmt_tags(result.tags),
        ]

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.awslambda.client import LambdaClient


class LambdaScanType(StrEnum):
    INVENTORY = "INVENTORY"


@dataclass
class LambdaInventoryResult(AuditResult):
    function_aliases: list[str] | None = None
    function_description: str | None = None
    function_url: str | None = None
    function_url_auth_type: str | None = None
    function_architecture: str | None = None
    runtime: str | None = None
    code_size: int | None = None
    memory_size: int | None = None
    last_modified: str | None = None
    architecture: str | None = None
    environment_variables: dict[str, str] | None = None
    vpc_config_vpcid: str | None = None
    vpc_config_subnetid: list[str] | None = None
    timeout: int | None = None
    provisioned_concurrency_config: str | None = None
    reserved_concurrency_limit: int | None = None
    billing_duration_ms: float | None = None
    estimated_monthly_cost: float | None = None
    dead_letter_queue_config: str | None = None
    cold_start_count: int | None = None
    warm_start_count: int | None = None
    average_duration_ms: float | None = None
    p95_duration_ms: float | None = None
    throttle_count: int | None = None
    concurrent_executions_peak: int | None = None
    concurrent_executions_average: float | None = None
    memory_utilization_percentage: float | None = None
    cpu_utilization_percentage: float | None = None
    network_bytes_in: float | None = None
    network_bytes_out: float | None = None
    storage_bytes_used: float | None = None
    kms_key_arn: str | None = None
    execution_role_arn: str | None = None
    layers: list[str] | None = None
    signing_profile_version_arn: str | None = None
    code_signing_config_arn: str | None = None
    event_source_mappings: list[str] | None = None
    destinations_on_success: str | None = None
    destinations_on_failure: str | None = None
    file_system_configs: list[str] | None = None
    image_config_entry_point: list[str] | None = None
    package_type: str | None = None
    tracing_config_mode: str | None = None
    log_retention_days: int | None = None
    insights_enabled: bool = False
    custom_metrics_count: int = 0
    creation_date: str | None = None
    last_invocation_date: str | None = None
    version_count: int = 1
    state: str | None = None
    state_reason: str | None = None
    invocation_count: int | None = None
    duration: float | None = None
    error_count: int | None = None
    success_percentage: float | None = None
    ephemeral_storage: int | None = None
    recursive_loop: str | None = None
    triggers: list[str] | None = None
    tags: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Custom dictionary conversion to exclude AuditResult fields.
        """
        data = asdict(self)
        data.pop("status_score", None)
        data.pop("findings", None)
        return data


class LambdaInventoryScanner(BaseScanner[LambdaInventoryResult]):
    service_name = "Lambda"
    is_global_service = False

    def __init__(self, check_type: str, session, account_id):
        super().__init__(check_type, session, account_id)
        self.client = LambdaClient(session)

    def fetch_resources(self) -> Iterable[Any]:
        return self.client.list_functions()

    def analyze_resource(self, func: dict[str, Any]) -> LambdaInventoryResult:
        function_name = func.get("FunctionName")
        function_arn = func.get("FunctionArn")
        region = self.session.region_name

        tags = self.client.get_tags(function_arn)
        aliases = self.client.get_function_aliases(function_name)
        url, url_auth = self.client.get_function_url_details(function_name)
        event_sources = self.client.get_event_source_mappings(function_name)

        vpc_config = func.get("VpcConfig", {})
        vpc_id = vpc_config.get("VpcId")
        subnet_ids = vpc_config.get("SubnetIds")

        env_vars = func.get("Environment", {}).get("Variables")

        layers = [layer["Arn"] for layer in func.get("Layers", [])]
        fs_configs = [fs["Arn"] for fs in func.get("FileSystemConfigs", [])]
        architectures = func.get("Architectures", ["x86_64"])
        arch_str = ", ".join(architectures)

        entry_point = (
            func.get("ImageConfigResponse", {}).get("ImageConfig", {}).get("EntryPoint")
        )

        invocations = self.client.get_metric_sum("Invocations", function_name)
        errors = self.client.get_metric_sum("Errors", function_name)
        throttles = self.client.get_metric_sum("Throttles", function_name)
        duration_avg = self.client.get_metric_avg("Duration", function_name)
        duration_max = self.client.get_metric_max("Duration", function_name)
        concurrent_peak = self.client.get_metric_max(
            "ConcurrentExecutions", function_name
        )

        mem_used = self.client.get_lambda_insight_metric(
            "memory_utilization", function_name
        )
        cpu_used = self.client.get_lambda_insight_metric(
            "cpu_total_time", function_name
        )

        success_rate = None
        if invocations > 0:
            success_rate = round(((invocations - errors) / invocations) * 100, 2)

        est_cost = None
        mem_size = func.get("MemorySize", 128)

        price_per_gb_sec = 0.0000166667
        if "arm64" in architectures:
            price_per_gb_sec = 0.0000133334

        if duration_avg is not None and invocations > 0:
            mem_gb = mem_size / 1024
            duration_seconds = duration_avg / 1000
            gb_seconds = mem_gb * duration_seconds * invocations
            request_cost = (invocations / 1_000_000) * 0.20
            compute_cost = gb_seconds * price_per_gb_sec
            est_cost = round(compute_cost + request_cost, 4)

        log_group_name = func.get("LoggingConfig", {}).get(
            "LogGroup", f"/aws/lambda/{function_name}"
        )
        log_retention = self.client.get_log_retention(log_group_name)

        return LambdaInventoryResult(
            resource_arn=function_arn,
            resource_name=function_name,
            region=region,
            account_id=self.account_id,
            function_aliases=aliases or None,
            function_description=func.get("Description") or None,
            function_url=url,
            function_url_auth_type=url_auth,
            function_architecture=arch_str,
            runtime=func.get("Runtime"),
            code_size=func.get("CodeSize"),
            memory_size=mem_size,
            last_modified=func.get("LastModified"),
            architecture=arch_str,
            environment_variables=env_vars,
            vpc_config_vpcid=vpc_id,
            vpc_config_subnetid=subnet_ids,
            timeout=func.get("Timeout"),
            provisioned_concurrency_config=None,
            reserved_concurrency_limit=func.get("ReservedConcurrentExecutions"),
            billing_duration_ms=duration_avg,
            estimated_monthly_cost=est_cost,
            dead_letter_queue_config=func.get("DeadLetterConfig", {}).get("TargetArn"),
            cold_start_count=None,
            warm_start_count=None,
            average_duration_ms=duration_avg,
            p95_duration_ms=duration_max,
            throttle_count=int(throttles) if throttles is not None else 0,
            concurrent_executions_peak=int(concurrent_peak)
            if concurrent_peak is not None
            else 0,
            concurrent_executions_average=None,
            memory_utilization_percentage=mem_used,
            cpu_utilization_percentage=cpu_used,
            network_bytes_in=None,
            network_bytes_out=None,
            storage_bytes_used=None,
            kms_key_arn=func.get("KMSKeyArn"),
            execution_role_arn=func.get("Role"),
            layers=layers or None,
            signing_profile_version_arn=func.get("SigningProfileVersionArn"),
            code_signing_config_arn=func.get("CodeSigningConfigArn"),
            event_source_mappings=event_sources or None,
            destinations_on_success=None,
            destinations_on_failure=None,
            file_system_configs=fs_configs or None,
            image_config_entry_point=entry_point,
            package_type=func.get("PackageType"),
            tracing_config_mode=func.get("TracingConfig", {}).get("Mode"),
            log_retention_days=log_retention,
            insights_enabled=bool(mem_used),
            custom_metrics_count=0,
            creation_date=func.get("LastModified"),
            last_invocation_date=None,
            version_count=1,
            state=func.get("State"),
            state_reason=func.get("StateReason"),
            invocation_count=int(invocations) if invocations is not None else 0,
            duration=duration_avg,
            error_count=int(errors) if errors is not None else 0,
            success_percentage=success_rate,
            ephemeral_storage=func.get("EphemeralStorage", {}).get("Size", 512),
            recursive_loop=func.get("RecursiveLoop"),
            triggers=event_sources or None,
            tags=tags or None,
        )

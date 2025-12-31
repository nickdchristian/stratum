from typing import Any

from strato.services.ec2.domains.inventory.checks import EC2InventoryResult


class EC2InventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "name",
            "account_id",
            "region",
            "instance_id",
            "instance_type",
            "state",
            "tags",
            "availability_zone",
            "private_ip",
            "private_ip6",
            "public_ip4",
            "elastic_ip",
            "launch_time",
            "platform",
            "managed",
            "architecture",
            "instance_lifecycle",
            "reserved_instance",
            "image_id",
            "ami_name",
            "ami_owner_alias",
            "source_ami_id",
            "ami_create_date",
            "marketplace_ami",
            "vpc_id",
            "subnet_id",
            "root_device_type",
            "highest_cpu_14_days",
            "highest_cpu_percentage_last_90_days",
            "highest_memory_percentage_last_14_days",
            "highest_memory_percentage_last_90_days",
            "attached_volumes",
            "attached_volume_encryption_status",
            "delete_on_termination_status",
            "hourly_cost",
            "monthly_cost_estimate",
            "savings_plan_coverage",
            "spot_price",
            "ri_coverage",
            "network_utilization_last_14_days",
            "network_utilization_last_90_days",
            "idle_time_percentage",
            "rightsizing_recommendation",
            "cost_center",
            "environment",
            "owner",
            "backup_policy",
            "generation_age",
            "burstable_credit_balance",
            "placement_group",
            "tenancy",
            "hibernation_enabled",
            "security_groups_count",
            "security_group_list",
            "security_group_inbound_ports",
            "security_group_outbound_ports",
            "iam_instance_profile",
            "monitoring_enabled",
            "termination_protection",
            "last_stop_date",
        ]

    @classmethod
    def format_row(cls, result: EC2InventoryResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: EC2InventoryResult) -> list[str]:
        """
        Converts the native typed result into a CSV-friendly string list.
        None -> "" (Empty String)
        List -> "Item1;Item2"
        Bool -> "True" / "False"
        """
        tags_string = "; ".join(f"{key}={value}" for key, value in result.tags.items())
        launch_string = result.launch_time.isoformat() if result.launch_time else ""

        def fmt(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, list):
                return ";".join(str(x) for x in val)
            return str(val)

        return [
            result.resource_name,
            result.account_id,
            result.region,
            result.resource_id,
            result.instance_type,
            result.state,
            tags_string,
            result.availability_zone,
            fmt(result.private_ip),
            fmt(result.private_ip6),
            fmt(result.public_ip4),
            fmt(result.elastic_ip),
            launch_string,
            fmt(result.platform),
            fmt(result.managed),
            fmt(result.architecture),
            fmt(result.instance_lifecycle),
            "",
            fmt(result.image_id),
            fmt(result.ami_name),
            fmt(result.ami_owner_alias),
            "",
            fmt(result.ami_create_date),
            "False",
            fmt(result.vpc_id),
            fmt(result.subnet_id),
            fmt(result.root_device_type),
            fmt(result.highest_cpu_14_days),
            fmt(result.highest_cpu_90_days),
            fmt(result.highest_memory_14_days),
            fmt(result.highest_memory_90_days),
            fmt(result.attached_volumes),
            fmt(result.attached_volume_encryption_status),
            fmt(result.delete_on_termination_status),
            "",
            "",
            "",
            "",
            "",
            fmt(result.network_util_14_days),
            fmt(result.network_util_90_days),
            "",
            fmt(result.rightsizing_recommendation),
            result.tags.get("CostCenter", ""),
            result.tags.get("Environment", ""),
            result.tags.get("Owner", ""),
            "",
            "",
            "0",
            "",
            "default",
            "False",
            fmt(result.security_groups_count),
            fmt(result.security_group_list),
            fmt(result.security_group_inbound_ports),
            fmt(result.security_group_outbound_ports),
            fmt(result.iam_instance_profile),
            fmt(result.monitoring_enabled),
            fmt(result.termination_protection),
            "",
        ]

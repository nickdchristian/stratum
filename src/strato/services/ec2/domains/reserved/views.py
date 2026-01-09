from typing import Any

from strato.services.ec2.domains.reserved.checks import EC2ReservedInstanceResult


class EC2ReservedInstanceView:
    @classmethod
    def get_headers(cls, check_type: str = None) -> list[str]:
        return [
            "account_id",
            "region",
            "id",
            "instance_type",
            "scope",
            "availability_zone",
            "instance_count",
            "start",
            "expires",
            "term_days",
            "payment_options",
            "offering_class",
            "upfront_price",
            "usage_price",
            "hourly_charges",
            "currency",
            "platform",
            "tenancy",
            "state",
            "remaining_days",
            "tags",
        ]

    @classmethod
    def format_row(cls, result: EC2ReservedInstanceResult) -> list[str]:
        def fmt(val: Any) -> str:
            return str(val) if val is not None else ""

        # Convert term seconds to days for readability
        term_days = result.term_seconds // 86400

        # Flatten tags dict for CSV/Table display
        tags_str = "; ".join([f"{k}={v}" for k, v in result.tags.items()])

        return [
            result.account_id,
            result.region,
            result.ri_id,
            result.instance_type,
            result.scope,
            result.availability_zone,
            fmt(result.instance_count),
            result.start,
            result.expires,
            fmt(term_days),
            result.payment_options,
            result.offering_class,
            fmt(result.upfront_price),
            fmt(result.usage_price),
            result.recurring_charges,
            result.currency_code,
            result.platform,
            result.tenancy,
            result.state,
            fmt(result.remaining_days),
            tags_str,
        ]

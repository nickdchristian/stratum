from typing import Any

from strato.services.rds.domains.reserved.checks import RDSReservedInstanceResult


class RDSReservedInstanceView:
    @classmethod
    def get_headers(cls, check_type: str = None) -> list[str]:
        # check_type arg is kept for signature compatibility with the runner
        return [
            "account_id",
            "region",
            "reservation_id",
            "lease_id",
            "product",
            "class",
            "offering_type",
            "status",
            "multi_az",
            "start_date",
            "remaining_days",
            "quantity",
        ]

    @classmethod
    def format_row(cls, result: RDSReservedInstanceResult) -> list[str]:
        def fmt(val: Any) -> str:
            return str(val) if val is not None else ""

        return [
            result.account_id,
            result.region,
            result.reservation_id,
            result.lease_id,
            result.product,
            result.class_type,
            result.offering_type,
            result.status,
            fmt(result.multi_az),
            result.start_date,
            fmt(result.remaining_days),
            fmt(result.quantity),
        ]

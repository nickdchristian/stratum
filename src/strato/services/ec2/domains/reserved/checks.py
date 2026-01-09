from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.ec2.client import EC2Client


class EC2ReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


@dataclass
class EC2ReservedInstanceResult(AuditResult):
    """
    Data container for EC2 Reserved Instances.
    """

    account_id: str = "Unknown"
    region: str = ""
    ri_id: str = ""
    instance_type: str = ""
    scope: str = ""
    availability_zone: str = ""
    instance_count: int = 0
    start: str = ""
    expires: str = ""
    term_seconds: int = 0
    payment_options: str = ""
    offering_class: str = ""
    upfront_price: float = 0.0
    usage_price: float = 0.0
    currency_code: str = ""
    recurring_charges: str = ""
    platform: str = ""
    tenancy: str = ""
    state: str = ""
    remaining_days: int = 0
    tags: dict[str, str] = field(default_factory=dict)

    # Required generic fields
    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""

    check_type: str = EC2ReservedScanType.RESERVED_INSTANCES

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = ["findings", "status_score", "status_score_reason"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class EC2ReservedInstanceScanner(BaseScanner[EC2ReservedInstanceResult]):
    def __init__(
        self,
        check_type: str = EC2ReservedScanType.RESERVED_INSTANCES,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = EC2Client(session=self.session)

    @property
    def service_name(self) -> str:
        return "EC2 Reserved Instances"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.get_reserved_instances()

    def analyze_resource(self, ri_data: dict) -> EC2ReservedInstanceResult:
        start_date = ri_data.get("Start")
        remaining_days = 0
        end_date = ri_data.get("End")

        if start_date:
            duration = ri_data.get("Duration", 0)
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        # Format recurring charges if present
        charges = ri_data.get("RecurringCharges", [])
        charges_str = (
            ", ".join([f"{c.get('Amount')}/{c.get('Frequency')}" for c in charges])
            if charges
            else "None"
        )

        tags_list = ri_data.get("Tags", [])
        tags_dict = {t.get("Key"): t.get("Value") for t in tags_list}

        ri_id = ri_data.get("ReservedInstancesId", "")

        return EC2ReservedInstanceResult(
            account_id=self.account_id,
            region=self.client.session.region_name,
            ri_id=ri_id,
            instance_type=ri_data.get("InstanceType", ""),
            scope=ri_data.get("Scope", ""),
            availability_zone=ri_data.get("AvailabilityZone", "Region"),
            instance_count=ri_data.get("InstanceCount", 0),
            start=start_date.isoformat() if start_date else "",
            expires=end_date.isoformat() if end_date else "",
            term_seconds=ri_data.get("Duration", 0),
            payment_options=ri_data.get("OfferingType", ""),
            offering_class=ri_data.get("OfferingClass", ""),
            upfront_price=ri_data.get("FixedPrice", 0.0),
            usage_price=ri_data.get("UsagePrice", 0.0),
            currency_code=ri_data.get("CurrencyCode", ""),
            recurring_charges=charges_str,
            platform=ri_data.get("ProductDescription", ""),
            tenancy=ri_data.get("InstanceTenancy", ""),
            state=ri_data.get("State", ""),
            remaining_days=int(remaining_days),
            tags=tags_dict,
            resource_id=ri_id,
            resource_name=ri_id,
            resource_arn=f"arn:aws:ec2:{self.client.session.region_name}:{self.account_id}:reserved-instances/{ri_id}",
            check_type=self.check_type,
        )

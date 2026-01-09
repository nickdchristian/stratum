from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner
from strato.services.rds.client import RDSClient


class RDSReservedScanType(StrEnum):
    RESERVED_INSTANCES = auto()


@dataclass
class RDSReservedInstanceResult(AuditResult):
    """
    Data container for RDS Reserved Instances.
    """

    account_id: str = "Unknown"
    region: str = ""
    reservation_id: str = ""
    lease_id: str = ""
    product: str = ""
    class_type: str = ""
    offering_type: str = ""
    status: str = ""
    multi_az: bool = False
    start_date: str = ""
    remaining_days: int = 0
    quantity: int = 0

    resource_arn: str = ""
    resource_id: str = ""
    resource_name: str = ""

    check_type: str = RDSReservedScanType.RESERVED_INSTANCES

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        keys_to_remove = ["findings", "status_score", "status_score_reason"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data


class RDSReservedInstanceScanner(BaseScanner[RDSReservedInstanceResult]):
    def __init__(
        self,
        check_type: str = RDSReservedScanType.RESERVED_INSTANCES,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = RDSClient(session=self.session)

    @property
    def service_name(self) -> str:
        return "RDS Reserved Instances"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.get_reserved_instances()

    def analyze_resource(self, ri_data: dict) -> RDSReservedInstanceResult:
        start_date = ri_data.get("StartTime")
        remaining_days = 0
        if start_date:
            duration = ri_data.get("Duration", 0)
            elapsed = (datetime.now(UTC) - start_date).days
            remaining_days = max(0, duration // 86400 - elapsed)

        return RDSReservedInstanceResult(
            account_id=self.account_id,
            region=self.client.session.region_name,
            reservation_id=ri_data.get("ReservedDBInstanceId", ""),
            lease_id=ri_data.get("LeaseId", ""),
            product=ri_data.get("ProductDescription", ""),
            class_type=ri_data.get("DBInstanceClass", ""),
            offering_type=ri_data.get("OfferingType", ""),
            status=ri_data.get("State", ""),
            multi_az=ri_data.get("MultiAZ", False),
            start_date=start_date.isoformat() if start_date else "",
            remaining_days=int(remaining_days),
            quantity=ri_data.get("DBInstanceCount", 0),
            resource_id=ri_data.get("ReservedDBInstanceId", ""),
            resource_name=ri_data.get("ReservedDBInstanceId", ""),
            check_type=self.check_type,
        )

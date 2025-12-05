from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult
from strato.core.scanner import BaseScanner
from strato.core.scoring import RiskWeight
from strato.services.s3.client import S3Client


class S3SecurityScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()


@dataclass
class S3SecurityResult(AuditResult):
    """
    Data model for S3 Security findings.
    """

    creation_date: datetime = None
    public_access_blocked: bool = False
    encryption: str = "None"
    check_type: str = S3SecurityScanType.ALL

    def __post_init__(self):
        """Automatically calculate risk after initialization."""
        self._evaluate_risk()

    def _evaluate_risk(self):
        """
        Calculates the risk score based on configured rules.

        Logic:
        - Public Access: Critical risk (exposed to internet).
        - No Encryption: Medium risk (compliance violation, but requires read access).
        """
        self.risk_score = 0
        self.risk_reasons = []

        # Check: Public Access Block
        if self.check_type in [
            S3SecurityScanType.ALL,
            S3SecurityScanType.PUBLIC_ACCESS,
        ]:
            if not self.public_access_blocked:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        # Check: Default Encryption
        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.ENCRYPTION]:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

    def to_dict(self) -> dict[str, Any]:
        """Override to handle datetime serialization."""
        data = asdict(self)
        if self.creation_date:
            data["creation_date"] = self.creation_date.isoformat()
        return data

    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        """Dynamic headers based on the specific scan type requested."""
        base_columns = ["Bucket Name", "Region"]
        risk_columns = ["Risk Level", "Reasons"]

        if check_type == S3SecurityScanType.ENCRYPTION:
            return base_columns + ["Encryption"] + risk_columns

        if check_type == S3SecurityScanType.PUBLIC_ACCESS:
            return base_columns + ["Public Blocked"] + risk_columns

        return (
            base_columns
            + ["Creation Date", "Public Blocked", "Encryption"]
            + risk_columns
        )

    def get_table_row(self) -> list[str]:
        """Formatted row with color-coding for S3 specific attributes."""
        base_row = super().get_table_row()
        risk_level_render = base_row[2]
        risk_reasons_render = base_row[3]

        public_access_render = (
            "[green]Blocked[/green]"
            if self.public_access_blocked
            else "[red]OPEN[/red]"
        )
        date_render = (
            self.creation_date.strftime("%Y-%m-%d") if self.creation_date else "Unknown"
        )

        if self.encryption == "None":
            encryption_render = "[yellow]Missing[/yellow]"
        else:
            encryption_render = f"[green]{self.encryption}[/green]"

        return self._build_row(
            date_render,
            public_access_render,
            encryption_render,
            risk_level_render,
            risk_reasons_render,
        )

    def get_csv_row(self) -> list[str]:
        """Raw CSV row for S3 attributes."""
        base_row = super().get_csv_row()
        risk_level_render = base_row[2]
        risk_reasons_render = base_row[3]

        date_render = (
            self.creation_date.isoformat() if self.creation_date else "Unknown"
        )
        public_access_render = "Blocked" if self.public_access_blocked else "OPEN"
        encryption_render = self.encryption

        return self._build_row(
            date_render,
            public_access_render,
            encryption_render,
            risk_level_render,
            risk_reasons_render,
        )

    def _build_row(
        self,
        date_render,
        public_access_render,
        encryption_render,
        risk_level_render,
        risk_reasons_render,
    ) -> list[str]:
        """Helper to assemble row columns based on scan type."""
        if self.check_type == S3SecurityScanType.ENCRYPTION:
            return [
                self.resource_name,
                self.region,
                encryption_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            return [
                self.resource_name,
                self.region,
                public_access_render,
                risk_level_render,
                risk_reasons_render,
            ]

        return [
            self.resource_name,
            self.region,
            date_render,
            public_access_render,
            encryption_render,
            risk_level_render,
            risk_reasons_render,
        ]


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    """
    Implementation of BaseScanner for S3.
    Aggregates data from multiple API calls to build a complete picture of a bucket.
    """

    def __init__(self, check_type: str = S3SecurityScanType.ALL):
        super().__init__(check_type)
        self.client = S3Client()

    @property
    def service_name(self) -> str:
        return f"S3 Security ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        """Yields simple bucket dictionaries to the thread pool."""
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: dict) -> S3SecurityResult:
        """
        Enriches a bucket dictionary with detailed security configurations.
        Performs additional API calls (Region, Public Access, Encryption).
        """
        bucket_arn = bucket_data["BucketArn"]
        bucket_name = bucket_data["Name"]

        region = self.client.get_bucket_region(bucket_name)
        creation_date = bucket_data["CreationDate"]

        public_access_blocked = self.client.get_public_access_status(bucket_name)
        encryption = self.client.get_encryption_status(bucket_name)
        check_type = self.check_type

        return S3SecurityResult(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_blocked=public_access_blocked,
            encryption=encryption,
            check_type=check_type,
        )

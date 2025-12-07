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
    ACLS = auto()
    VERSIONING = auto()


@dataclass
class S3SecurityResult(AuditResult):
    resource_arn: str
    resource_name: str
    region: str

    creation_date: datetime = None
    public_access_blocked: bool = False
    encryption: str = "None"
    acl_status: str = "Unknown"
    is_log_target: bool = False
    versioning: str = "Suspended"
    mfa_delete: str = "Disabled"
    check_type: str = S3SecurityScanType.ALL

    def __post_init__(self):
        self._evaluate_risk()

    def _evaluate_risk(self):
        self.risk_score = 0
        self.risk_reasons = []

        if self.check_type in [
            S3SecurityScanType.ALL,
            S3SecurityScanType.PUBLIC_ACCESS,
        ]:
            if not self.public_access_blocked:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.ENCRYPTION]:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.ACLS]:
            if self.acl_status == "Enabled":
                if self.is_log_target:
                    self.risk_score += RiskWeight.MEDIUM
                    self.risk_reasons.append("Legacy ACLs (Required for Logging)")
                else:
                    self.risk_score += RiskWeight.HIGH
                    self.risk_reasons.append("Legacy ACLs Enabled")

        if self.check_type in [S3SecurityScanType.ALL, S3SecurityScanType.VERSIONING]:
            if self.versioning != "Enabled":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Versioning Disabled")
            elif self.mfa_delete != "Enabled":
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("MFA Delete Disabled")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.creation_date:
            data["creation_date"] = self.creation_date.isoformat()
        return data

    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        base_columns = ["Bucket Name", "Region"]
        risk_columns = ["Risk Level", "Reasons"]

        if check_type == S3SecurityScanType.ENCRYPTION:
            return base_columns + ["Encryption"] + risk_columns

        if check_type == S3SecurityScanType.PUBLIC_ACCESS:
            return base_columns + ["Public Blocked"] + risk_columns

        if check_type == S3SecurityScanType.ACLS:
            return base_columns + ["ACL Status", "Log Target"] + risk_columns

        if check_type == S3SecurityScanType.VERSIONING:
            return base_columns + ["Versioning", "MFA Delete"] + risk_columns

        return base_columns + risk_columns

    def get_table_row(self) -> list[str]:
        base_row = super().get_table_row()

        resource_name = base_row[0]
        region = base_row[1]
        risk_level_render = base_row[2]
        risk_reasons_render = base_row[3]

        if self.check_type == S3SecurityScanType.ENCRYPTION:
            enc_render = (
                f"[green]{self.encryption}[/green]"
                if self.encryption != "None"
                else "[yellow]Missing[/yellow]"
            )
            return [
                resource_name,
                region,
                enc_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            pub_render = (
                "[green]Blocked[/green]"
                if self.public_access_blocked
                else "[red]OPEN[/red]"
            )
            return [
                resource_name,
                region,
                pub_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.ACLS:
            if self.acl_status == "Disabled":
                acl_render = "[green]Disabled[/green]"
            elif self.is_log_target:
                acl_render = "[yellow]Enabled (Logs)[/yellow]"
            else:
                acl_render = "[red]Enabled[/red]"
            log_target_render = "Yes" if self.is_log_target else "No"

            return [
                resource_name,
                region,
                acl_render,
                log_target_render,
                risk_level_render,
                risk_reasons_render,
            ]

        if self.check_type == S3SecurityScanType.VERSIONING:
            version_render = (
                f"[green]{self.versioning}[/green]"
                if self.versioning == "Enabled"
                else f"[red]{self.versioning}[/red]"
            )
            mfa_render = (
                f"[green]{self.mfa_delete}[/green]"
                if self.mfa_delete == "Enabled"
                else f"[yellow]{self.mfa_delete}[/yellow]"
            )
            return [
                resource_name,
                region,
                version_render,
                mfa_render,
                risk_level_render,
                risk_reasons_render,
            ]

        return base_row

    def get_csv_row(self) -> list[str]:
        date_render = (
            self.creation_date.isoformat() if self.creation_date else "Unknown"
        )
        public_render = "Blocked" if self.public_access_blocked else "OPEN"
        encryption_render = self.encryption
        acl_render = self.acl_status
        log_target_render = str(self.is_log_target)
        risk_reasons_str = "; ".join(self.risk_reasons)

        return [
            self.resource_name,
            self.region,
            date_render,
            public_render,
            encryption_render,
            acl_render,
            log_target_render,
            self.versioning,
            self.mfa_delete,
            self.risk_level,
            risk_reasons_str,
        ]


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    def __init__(self, check_type: str = S3SecurityScanType.ALL):
        super().__init__(check_type)
        self.client = S3Client()

    @property
    def service_name(self) -> str:
        return f"S3 Security ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: dict) -> S3SecurityResult:
        bucket_arn = bucket_data.get("BucketArn", f"arn:aws:s3:::{bucket_data['Name']}")
        bucket_name = bucket_data["Name"]
        region = self.client.get_bucket_region(bucket_name)
        creation_date = bucket_data["CreationDate"]

        public_access_blocked = self.client.get_public_access_status(bucket_name)
        encryption = self.client.get_encryption_status(bucket_name)

        acl_status = self.client.get_acl_status(bucket_name)
        is_log_target = False
        if acl_status == "Enabled":
            is_log_target = self.client.is_log_target(bucket_name)

        version_config = self.client.get_versioning_status(bucket_name)

        return S3SecurityResult(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_blocked=public_access_blocked,
            encryption=encryption,
            acl_status=acl_status,
            is_log_target=is_log_target,
            versioning=version_config["Status"],
            mfa_delete=version_config["MFADelete"],
            check_type=self.check_type,
        )

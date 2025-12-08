from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult
from strato.core.scanner import BaseScanner
from strato.core.scoring import RiskWeight
from strato.core.style import AuditStatus, colorize
from strato.services.s3.client import S3Client


class S3SecurityScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()
    ACLS = auto()
    VERSIONING = auto()
    OBJECT_LOCK = auto()


@dataclass
class S3SecurityResult(AuditResult):
    resource_arn: str
    resource_name: str
    region: str

    creation_date: datetime = None
    public_access_blocked: bool = False
    encryption: str = "None"
    sse_c_blocked: bool = False
    acl_status: str = "Unknown"
    is_log_target: bool = False
    versioning: str = "Suspended"
    mfa_delete: str = "Disabled"
    object_lock: str = "Disabled"
    check_type: str = S3SecurityScanType.ALL

    def __post_init__(self):
        self._evaluate_risk()

    def _evaluate_risk(self):
        self.risk_score = 0
        self.risk_reasons = []

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            if not self.public_access_blocked:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

        if not self.sse_c_blocked:
            self.risk_score += RiskWeight.LOW
            self.risk_reasons.append("SSE-C Not Blocked")

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            if self.acl_status == "Enabled":
                if self.is_log_target:
                    self.risk_score += RiskWeight.MEDIUM
                    self.risk_reasons.append("Legacy ACLs (Required for Logging)")
                else:
                    self.risk_score += RiskWeight.HIGH
                    self.risk_reasons.append("Legacy ACLs Enabled")

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            if self.versioning != "Enabled":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Versioning Disabled")
            elif self.mfa_delete != "Enabled":
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("MFA Delete Disabled")

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            if self.object_lock != "Enabled":
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("Object Lock Disabled")

    def _get_scan_columns(self) -> list[tuple[str, str, Any, str]]:
        """
        Registry of dynamic columns.
        Format: (Header Name, JSON Key, Raw Value, Table Render)
        """
        columns = []
        is_all = self.check_type == S3SecurityScanType.ALL

        # Only add columns if relevant to the check_type (or ALL)
        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            columns.append(
                (
                    "Public Blocked",
                    "public_access_blocked",
                    self.public_access_blocked,
                    self._render_public,
                )
            )

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            columns.append(
                ("Encryption", "encryption", self.encryption, self._render_encryption)
            )
            columns.append(
                (
                    "SSE-C Blocked",
                    "sse_c_blocked",
                    self.sse_c_blocked,
                    self._render_ssec,
                )
            )

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            columns.append(
                ("ACL Status", "acl_status", self.acl_status, self._render_acl)
            )
            columns.append(
                (
                    "Log Target",
                    "is_log_target",
                    self.is_log_target,
                    "Yes" if self.is_log_target else "No",
                )
            )

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            columns.append(
                ("Versioning", "versioning", self.versioning, self._render_versioning)
            )
            columns.append(
                ("MFA Delete", "mfa_delete", self.mfa_delete, self._render_mfa)
            )

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            columns.append(
                ("Object Lock", "object_lock", self.object_lock, self._render_lock)
            )

        return columns

    def to_dict(self) -> dict[str, Any]:
        """JSON always includes the full data set."""
        data = {
            "resource_arn": self.resource_arn,
            "resource_name": self.resource_name,
            "region": self.region,
            "creation_date": self.creation_date.isoformat()
            if self.creation_date
            else None,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_reasons": self.risk_reasons,
            "check_type": self.check_type,
        }
        for _, key, value, _ in self._get_scan_columns():
            data[key] = value
        return data

    @classmethod
    def get_csv_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        """
        CSV Headers: ALWAYS returns the full set of columns (Base + Dynamic + Risk).
        """
        dummy = cls(resource_arn="", resource_name="", region="", check_type=check_type)
        base_headers = ["Bucket Name", "Region", "Creation Date"]
        dynamic_headers = [col[0] for col in dummy._get_scan_columns()]
        risk_headers = ["Risk Level", "Reasons"]

        return base_headers + dynamic_headers + risk_headers

    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        """
        Table Headers: Returns a SUMMARY for 'ALL' scans to keep the table readable.
        For specific scans, it returns the full details (same as CSV).
        """
        if check_type == S3SecurityScanType.ALL:
            return ["Bucket Name", "Region", "Creation Date", "Risk Level", "Reasons"]

        return cls.get_csv_headers(check_type)

    def get_csv_row(self) -> list[str]:
        """CSV Row: Aligns with get_csv_headers (Always Full)."""
        date_str = self.creation_date.isoformat() if self.creation_date else "Unknown"
        row = [self.resource_name, self.region, date_str]

        # Always inject dynamic columns
        for _, _, val, _ in self._get_scan_columns():
            if isinstance(val, bool):
                row.append("Yes" if val else "No")
            else:
                row.append(str(val))

        row.append(self.risk_level)
        row.append("; ".join(self.risk_reasons))
        return row

    def get_table_row(self) -> list[str]:
        """Table Row: Aligns with get_headers (Summary for ALL, Full for others)."""
        base_row = super().get_table_row()

        resource_name = base_row[0]
        region = base_row[1]
        risk_level = base_row[2]
        risk_reasons = base_row[3]

        date_str = (
            self.creation_date.strftime("%Y-%m-%d") if self.creation_date else "Unknown"
        )
        row = [resource_name, region, date_str]

        # Only inject dynamic columns if NOT 'ALL' (Risk-Only View)
        if self.check_type != S3SecurityScanType.ALL:
            for _, _, _, render in self._get_scan_columns():
                row.append(render)

        row.append(risk_level)
        row.append(risk_reasons)

        return row

    @property
    def _render_encryption(self):
        if self.encryption != "None":
            return colorize(self.encryption, AuditStatus.PASS)
        return colorize("Missing", AuditStatus.WARN)

    @property
    def _render_ssec(self):
        if self.sse_c_blocked:
            return colorize("Blocked", AuditStatus.PASS)
        return colorize("Allowed", AuditStatus.WARN)

    @property
    def _render_public(self):
        if self.public_access_blocked:
            return colorize("Blocked", AuditStatus.PASS)
        return colorize("OPEN", AuditStatus.FAIL)

    @property
    def _render_acl(self):
        if self.acl_status == "Disabled":
            return colorize("Disabled", AuditStatus.PASS)

        status_text = "Enabled (Logs)" if self.is_log_target else "Enabled"
        color = AuditStatus.WARN if self.is_log_target else AuditStatus.FAIL

        return colorize(status_text, color)

    @property
    def _render_versioning(self):
        color = AuditStatus.PASS if self.versioning == "Enabled" else AuditStatus.FAIL
        return colorize(self.versioning, color)

    @property
    def _render_mfa(self):
        color = AuditStatus.PASS if self.mfa_delete == "Enabled" else AuditStatus.WARN
        return colorize(self.mfa_delete, color)

    @property
    def _render_lock(self):
        color = AuditStatus.PASS if self.object_lock == "Enabled" else AuditStatus.WARN
        return colorize(self.object_lock, color)


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

        public_access_blocked = False
        encryption = "None"
        sse_c_blocked = False
        acl_status = "Unknown"
        is_log_target = False
        version_config = {"Status": "Suspended", "MFADelete": "Disabled"}
        object_lock = "Disabled"

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            public_access_blocked = self.client.get_public_access_status(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            enc_status = self.client.get_encryption_status(bucket_name)
            encryption = enc_status["SSEAlgorithm"]
            sse_c_blocked = enc_status["SSECBlocked"]

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            acl_status = self.client.get_acl_status(bucket_name)
            if acl_status == "Enabled":
                is_log_target = self.client.is_log_target(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            version_config = self.client.get_versioning_status(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            object_lock = self.client.get_object_lock_status(bucket_name)

        return S3SecurityResult(
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_blocked=public_access_blocked,
            encryption=encryption,
            sse_c_blocked=sse_c_blocked,
            acl_status=acl_status,
            is_log_target=is_log_target,
            versioning=version_config["Status"],
            mfa_delete=version_config["MFADelete"],
            object_lock=object_lock,
            check_type=self.check_type,
        )

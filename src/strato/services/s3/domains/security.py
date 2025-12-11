from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult
from strato.core.scanner import BaseScanner
from strato.core.scoring import RiskWeight
from strato.core.style import AuditStatus, colorize
from strato.services.s3 import utils
from strato.services.s3.client import S3Client


class S3SecurityScanType(StrEnum):
    ALL = auto()
    ENCRYPTION = auto()
    PUBLIC_ACCESS = auto()
    POLICY = auto()
    ACLS = auto()
    VERSIONING = auto()
    OBJECT_LOCK = auto()
    NAME_PREDICTABILITY = auto()
    WEBSITE_HOSTING = auto()


@dataclass
class S3SecurityResult(AuditResult):
    resource_arn: str
    resource_name: str
    region: str
    account_id: str

    creation_date: datetime = None
    public_access_block_status: bool = False
    policy_access: str = "Unknown"
    ssl_enforced: bool = False
    encryption: str = "None"
    sse_c: bool = False
    acl_status: str = "Unknown"
    log_target: bool = False
    versioning: str = "Suspended"
    mfa_delete: str = "Disabled"
    object_lock: str = "Disabled"
    name_predictability: str = "LOW"
    website_hosting: bool | None = None
    log_sources: list[str] = field(default_factory=list)
    check_type: str = S3SecurityScanType.ALL

    def __post_init__(self):
        self._evaluate_risk()

    def _evaluate_risk(self):
        self.risk_score = 0
        self.risk_reasons = []

        is_all = self.check_type == S3SecurityScanType.ALL
        is_critical_log_bucket = len(self.log_sources) > 0

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            if not self.public_access_block_status:
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Public Access Allowed")

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            if not self.ssl_enforced:
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("SSL Not Enforced")
            if self.policy_access == "Public":
                self.risk_score += RiskWeight.CRITICAL
                self.risk_reasons.append("Bucket Policy Allows Public Access")
            if self.policy_access == "Potentially Public":
                self.risk_score += RiskWeight.HIGH
                self.risk_reasons.append(
                    "Bucket Policy Potentially Allows Public Access"
                )

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            if self.encryption == "None":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Encryption Missing")

            if not self.sse_c:
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("SSE-C Not Blocked")

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            if self.acl_status == "Enabled":
                if self.log_target:
                    self.risk_score += RiskWeight.MEDIUM
                    self.risk_reasons.append("Legacy ACLs (Required for Logging)")
                else:
                    self.risk_score += RiskWeight.HIGH
                    self.risk_reasons.append("Legacy ACLs Enabled")

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            if self.versioning != "Enabled":
                self.risk_score += RiskWeight.MEDIUM
                self.risk_reasons.append("Versioning Disabled")
            elif self.mfa_delete != "Enabled" and is_critical_log_bucket:
                self.risk_score += RiskWeight.LOW
                formatted_sources = ", ".join(self.log_sources)
                self.risk_reasons.append(
                    f"MFA Delete Disabled ({formatted_sources} Bucket)"
                )

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            if self.object_lock != "Enabled" and is_critical_log_bucket:
                self.risk_score += RiskWeight.LOW
                formatted_sources = ", ".join(self.log_sources)
                self.risk_reasons.append(
                    f"Object Lock Disabled ({formatted_sources} Bucket)"
                )

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            if self.name_predictability == "HIGH":
                self.risk_score += RiskWeight.LOW
                self.risk_reasons.append("Highly Predictable Bucket Name")
            if self.name_predictability == "MODERATE":
                self.risk_score += RiskWeight.NONE
                self.risk_reasons.append("Moderately Predictable Bucket Name")

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            if self.website_hosting:
                self.risk_score += RiskWeight.HIGH
                self.risk_reasons.append("Static Website Hosting Enabled")

    def _get_scan_columns(self) -> list[tuple[str, str, Any, str]]:
        """Registry of dynamic columns."""
        columns = []
        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            columns.append(
                (
                    "Public Access Block Status",
                    "public_access_blocked_status",
                    self.public_access_block_status,
                    self._render_public_access_block,
                )
            )

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            columns.append(
                (
                    "Policy Access",
                    "policy_access",
                    self.policy_access,
                    self._render_policy_access,
                )
            )

            columns.append(
                (
                    "SSL Enforced",
                    "ssl_enforced",
                    self.ssl_enforced,
                    self._render_ssl_enforced,
                )
            )
        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            columns.append(
                ("Encryption", "encryption", self.encryption, self._render_encryption)
            )
            columns.append(
                (
                    "SSE-C",
                    "sse_c",
                    self.sse_c,
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
                    "log_target",
                    self.log_target,
                    "Yes" if self.log_target else "No",
                )
            )

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            columns.append(
                ("Versioning", "versioning", self.versioning, self._render_versioning)
            )
            columns.append(
                ("MFA Delete", "mfa_delete", self.mfa_delete, self._render_mfa_delete)
            )

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            columns.append(
                (
                    "Object Lock",
                    "object_lock",
                    self.object_lock,
                    self._render_object_lock,
                )
            )

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            columns.append(
                (
                    "Name Predictability",
                    "name_predictability",
                    self.name_predictability,
                    self._render_name_predictability,
                )
            )
        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            columns.append(
                (
                    "Website Hosting",
                    "website_hosting",
                    self.website_hosting,
                    self._render_website_hosting,
                )
            )

        return columns

    def to_dict(self) -> dict[str, Any]:
        """JSON always includes the full data set."""
        data = {
            "account_id": self.account_id,
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
            "log_sources": self.log_sources,
        }
        for _, key, value, _ in self._get_scan_columns():
            data[key] = value
        return data

    @classmethod
    def get_csv_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        """CSV Headers."""
        dummy = cls(resource_arn="", resource_name="", region="", check_type=check_type)
        base_headers = ["Account ID", "Bucket Name", "Region", "Creation Date"]
        dynamic_headers = [col[0] for col in dummy._get_scan_columns()]
        risk_headers = ["Risk Level", "Reasons"]

        return base_headers + dynamic_headers + risk_headers

    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        """Table Headers."""
        if check_type == S3SecurityScanType.ALL:
            return [
                "Account ID",
                "Bucket Name",
                "Region",
                "Creation Date",
                "Risk Level",
                "Reasons",
            ]

        return cls.get_csv_headers(check_type)

    def get_csv_row(self) -> list[str]:
        """CSV Row."""
        date_str = self.creation_date.isoformat() if self.creation_date else "Unknown"
        row = [self.account_id, self.resource_name, self.region, date_str]

        for _, _, val, _ in self._get_scan_columns():
            if isinstance(val, bool):
                row.append("Yes" if val else "No")
            else:
                row.append(str(val))

        row.append(self.risk_level)
        row.append("; ".join(self.risk_reasons))
        return row

    def get_table_row(self) -> list[str]:
        """Table Row."""
        base_row = super().get_table_row()
        risk_level_render = base_row[-2]
        risk_reasons_render = base_row[-1]

        date_str = (
            self.creation_date.strftime("%Y-%m-%d") if self.creation_date else "Unknown"
        )

        row = [self.account_id, self.resource_name, self.region, date_str]

        if self.check_type != S3SecurityScanType.ALL:
            for _, _, _, render in self._get_scan_columns():
                row.append(render)

        row.append(risk_level_render)
        row.append(risk_reasons_render)

        return row

    @property
    def _render_encryption(self):
        if self.encryption != "None":
            return colorize(self.encryption, AuditStatus.PASS)
        return colorize("Missing", AuditStatus.WARN)

    @property
    def _render_ssec(self):
        if self.sse_c:
            return colorize("Blocked", AuditStatus.PASS)
        return colorize("Allowed", AuditStatus.WARN)

    @property
    def _render_public_access_block(self):
        if self.public_access_block_status:
            return colorize("Blocked", AuditStatus.PASS)
        return colorize("OPEN", AuditStatus.FAIL)

    @property
    def _render_policy_access(self):
        if self.policy_access == "Private":
            return colorize(self.policy_access, AuditStatus.PASS)
        if self.policy_access == "Potentially Public":
            return colorize(self.policy_access, AuditStatus.WARN)
        return colorize(self.policy_access, AuditStatus.FAIL)

    @property
    def _render_ssl_enforced(self):
        if self.ssl_enforced:
            return colorize("Yes", AuditStatus.PASS)
        return colorize("No", AuditStatus.FAIL)

    @property
    def _render_acl(self):
        if self.acl_status == "Disabled":
            return colorize("Disabled", AuditStatus.PASS)

        status_text = "Enabled (Logs)" if self.log_target else "Enabled"
        color = AuditStatus.WARN if self.log_target else AuditStatus.FAIL

        return colorize(status_text, color)

    @property
    def _render_versioning(self):
        color = AuditStatus.PASS if self.versioning == "Enabled" else AuditStatus.FAIL
        return colorize(self.versioning, color)

    @property
    def _render_mfa_delete(self):
        color = AuditStatus.PASS if self.mfa_delete == "Enabled" else AuditStatus.WARN
        return colorize(self.mfa_delete, color)

    @property
    def _render_object_lock(self):
        color = AuditStatus.PASS if self.object_lock == "Enabled" else AuditStatus.WARN
        return colorize(self.object_lock, color)

    @property
    def _render_name_predictability(self):
        if self.name_predictability == "LOW":
            return colorize(self.name_predictability, AuditStatus.PASS)
        return colorize(self.name_predictability, AuditStatus.WARN)

    @property
    def _render_website_hosting(self):
        if self.website_hosting:
            return colorize("Enabled", AuditStatus.WARN)
        return colorize("Disabled", AuditStatus.PASS)


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    def __init__(
        self,
        check_type: str = S3SecurityScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = S3Client(session=self.session)

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
        bucket_policy_config = {
            "Access": "Private",
            "SSL_Enforced": False,
            "Log_Sources": [],
        }
        encryption = "None"
        sse_c_blocked = False
        acl_status = "Unknown"
        is_log_target = False
        version_config = {"Status": "Suspended", "MFADelete": "Disabled"}
        object_lock = "Disabled"
        name_predictability = "HIGH"
        website_hosting = False

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            public_access_blocked = self.client.get_public_access_status(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            bucket_policy_config = self.client.get_bucket_policy(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            enc_status = self.client.get_encryption_status(bucket_name)
            encryption = enc_status["SSEAlgorithm"]
            sse_c_blocked = enc_status["SSECBlocked"]

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            acl_status = self.client.get_acl_status(bucket_name)
            if acl_status == "Enabled":
                is_log_target = self.client.log_target(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            version_config = self.client.get_versioning_status(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            object_lock = self.client.get_object_lock_status(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            name_predictability = utils.get_bucket_name_predictability(bucket_name)

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            website_hosting = self.client.get_website_hosting_status(bucket_name)

        return S3SecurityResult(
            account_id=self.account_id,
            resource_arn=bucket_arn,
            resource_name=bucket_name,
            region=region,
            creation_date=creation_date,
            public_access_block_status=public_access_blocked,
            policy_access=bucket_policy_config["Access"],
            ssl_enforced=bucket_policy_config["SSL_Enforced"],
            log_sources=bucket_policy_config["Log_Sources"],
            encryption=encryption,
            sse_c=sse_c_blocked,
            acl_status=acl_status,
            log_target=is_log_target,
            versioning=version_config["Status"],
            mfa_delete=version_config["MFADelete"],
            object_lock=object_lock,
            name_predictability=name_predictability,
            website_hosting=website_hosting,
            check_type=self.check_type,
        )

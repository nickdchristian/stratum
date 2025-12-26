from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult
from strato.core.scanner import BaseScanner
from strato.core.scoring import ObservationLevel
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
    """
    Pure Data Model.
    Holds the state of the resource and the evaluation of that state (findings).
    Does NOT contain logic for how to print or colorize this data.
    """
    resource_arn: str
    resource_name: str
    region: str
    account_id: str

    creation_date: datetime | None = None
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
        self._evaluate_status()

    def _evaluate_status(self):
        """
        Domain Logic: Evaluates the resource configuration against rules
        to determine the risk score and findings.
        """
        self.status_score = 0
        self.findings = []

        is_all = self.check_type == S3SecurityScanType.ALL
        is_critical_log_bucket = len(self.log_sources) > 0

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            if not self.public_access_block_status:
                self.status_score += ObservationLevel.CRITICAL
                self.findings.append("Public Access Allowed")

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            if not self.ssl_enforced:
                self.status_score += ObservationLevel.MEDIUM
                self.findings.append("SSL Not Enforced")
            if self.policy_access == "Public":
                self.status_score += ObservationLevel.CRITICAL
                self.findings.append("Bucket Policy Allows Public Access")
            if self.policy_access == "Potentially Public":
                self.status_score += ObservationLevel.HIGH
                self.findings.append("Bucket Policy Potentially Allows Public Access")

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            if self.encryption == "None":
                self.status_score += ObservationLevel.MEDIUM
                self.findings.append("Encryption Missing")
            if not self.sse_c:
                self.status_score += ObservationLevel.LOW
                self.findings.append("SSE-C Not Blocked")

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            if self.acl_status == "Enabled":
                if self.log_target:
                    self.status_score += ObservationLevel.MEDIUM
                    self.findings.append("Legacy ACLs (Required for Logging)")
                else:
                    self.status_score += ObservationLevel.HIGH
                    self.findings.append("Legacy ACLs Enabled")

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            if self.versioning != "Enabled":
                self.status_score += ObservationLevel.MEDIUM
                self.findings.append("Versioning Disabled")
            elif self.mfa_delete != "Enabled" and is_critical_log_bucket:
                self.status_score += ObservationLevel.LOW
                formatted_sources = ", ".join(self.log_sources)
                self.findings.append(
                    f"MFA Delete Disabled ({formatted_sources} Bucket)"
                )

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            if self.object_lock != "Enabled" and is_critical_log_bucket:
                self.status_score += ObservationLevel.LOW
                formatted_sources = ", ".join(self.log_sources)
                self.findings.append(
                    f"Object Lock Disabled ({formatted_sources} Bucket)"
                )

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            if self.name_predictability == "HIGH":
                self.status_score += ObservationLevel.LOW
                self.findings.append("Highly Predictable Bucket Name")
            if self.name_predictability == "MODERATE":
                self.status_score += ObservationLevel.INFO
                self.findings.append("Moderately Predictable Bucket Name")

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            if self.website_hosting:
                self.status_score += ObservationLevel.HIGH
                self.findings.append("Static Website Hosting Enabled")

    def to_dict(self) -> dict[str, Any]:
        """Simple data serialization."""
        return {
            "account_id": self.account_id,
            "resource_arn": self.resource_arn,
            "resource_name": self.resource_name,
            "region": self.region,
            "creation_date": self.creation_date.isoformat() if self.creation_date else None,
            "status_score": self.status_score,
            "status": self.status,
            "findings": self.findings,
            "check_type": self.check_type,
            "configuration": {
                "encryption": self.encryption,
                "public_access_blocked": self.public_access_block_status,
                "versioning": self.versioning,
            }
        }


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    """
    Orchestrates the fetching of S3 data and creation of S3SecurityResult objects.
    """
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
        creation_date = bucket_data.get("CreationDate")

        # Default / Zero Values
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

        # Fetch details based on check type
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
                is_log_target = self.client.is_log_target(bucket_name)

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
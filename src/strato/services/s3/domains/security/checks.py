import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, auto
from typing import Any

from strato.core.models import AuditResult, BaseScanner, ObservationLevel
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
    Data container for S3 Security and Configuration details.
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
    acl_status: str | None = "Unknown"
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
        data: dict[str, Any] = {
            "account_id": self.account_id,
            "resource_arn": self.resource_arn,
            "resource_name": self.resource_name,
            "region": self.region,
            "creation_date": self.creation_date.isoformat()
            if self.creation_date
            else None,
            "status_score": self.status_score,
            "status": self.status,
            "findings": self.findings,
            "check_type": self.check_type,
        }

        config = {}
        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            config["public_access_blocked"] = self.public_access_block_status

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            config["policy_access"] = self.policy_access
            config["ssl_enforced"] = self.ssl_enforced

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            config["encryption"] = self.encryption
            config["sse_c_blocked"] = self.sse_c

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            config["acl_status"] = self.acl_status
            config["log_target"] = self.log_target
            config["log_sources"] = self.log_sources

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            config["versioning"] = self.versioning
            config["mfa_delete"] = self.mfa_delete

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            config["object_lock"] = self.object_lock

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            config["name_predictability"] = self.name_predictability

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            config["website_hosting"] = self.website_hosting

        data["configuration"] = config
        return data


class S3SecurityScanner(BaseScanner[S3SecurityResult]):
    def __init__(
        self,
        check_type: str = S3SecurityScanType.ALL,
        session=None,
        account_id="Unknown",
    ):
        super().__init__(check_type, session, account_id)
        self.client = S3Client(session=self.session)

    is_global_service = True

    @property
    def service_name(self) -> str:
        return f"S3 Security ({self.check_type})"

    def fetch_resources(self) -> Iterable[dict]:
        yield from self.client.list_buckets()

    def analyze_resource(self, bucket_data: dict) -> S3SecurityResult:
        name = bucket_data["Name"]
        arn = bucket_data.get("BucketArn", f"arn:aws:s3:::{name}")
        created = bucket_data.get("CreationDate")
        region = self.client.get_bucket_region(name)

        pab_status = False
        policy = {"Access": "Unknown", "SSL_Enforced": False, "Log_Sources": []}
        encryption = {"SSEAlgorithm": "None", "SSECBlocked": False}

        acl_status = "Unknown"
        is_log_target = False
        versioning_status = "Suspended"
        mfa_delete_str = "Disabled"
        object_lock_str = "Disabled"
        predictability = "LOW"
        website_hosting = None

        is_all = self.check_type == S3SecurityScanType.ALL

        if is_all or self.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            pab_status = self.client.get_public_access_status(name)

        if is_all or self.check_type == S3SecurityScanType.POLICY:
            policy = self.client.get_bucket_policy(name)

        if is_all or self.check_type == S3SecurityScanType.ENCRYPTION:
            encryption = self.client.get_encryption_status(name)

        if is_all or self.check_type == S3SecurityScanType.ACLS:
            acl_status = self.client.get_acl_status(name)["Status"]

            if acl_status == "Enabled":
                is_log_target = self.client.is_log_target(name)

        if is_all or self.check_type == S3SecurityScanType.VERSIONING:
            v_data = self.client.get_versioning_status(name)
            versioning_status = v_data["Status"]
            mfa_delete_str = "Enabled" if v_data["MFADelete"] else "Disabled"

        if is_all or self.check_type == S3SecurityScanType.OBJECT_LOCK:
            lock_data = self.client.get_object_lock_details(name)
            object_lock_str = "Enabled" if lock_data["Status"] else "Disabled"

        if is_all or self.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            predictability = self._calculate_entropy(name)

        if is_all or self.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            website_hosting = self.client.get_website_hosting_status(name)

        return S3SecurityResult(
            account_id=self.account_id,
            resource_arn=arn,
            resource_name=name,
            region=region,
            creation_date=created,
            public_access_block_status=pab_status,
            policy_access=policy["Access"],
            ssl_enforced=policy["SSL_Enforced"],
            log_sources=policy["Log_Sources"],
            encryption=encryption["SSEAlgorithm"],
            sse_c=encryption.get("SSECBlocked", False),
            acl_status=acl_status,
            log_target=is_log_target,
            versioning=versioning_status,
            mfa_delete=mfa_delete_str,
            object_lock=object_lock_str,
            name_predictability=predictability,
            website_hosting=website_hosting,
            check_type=self.check_type,
        )

    @staticmethod
    def _calculate_entropy(bucket_name: str) -> str:
        """
        Calculates the predictability of a bucket name using Shannon entropy analysis.
        """
        entropy = 0
        has_guid_fragment = bool(re.search(r"[a-f0-9]{8,}", bucket_name))
        character_frequency = Counter(bucket_name)
        bucket_name_length = len(bucket_name)

        for frequency in character_frequency.values():
            probability = frequency / bucket_name_length
            entropy -= probability * math.log2(probability)

        if has_guid_fragment and entropy > 3.0:
            return "LOW"
        elif entropy < 2.5 or len(bucket_name) < 8:
            return "HIGH"
        else:
            return "MODERATE"

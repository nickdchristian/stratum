from typing import Any

from strato.core.style import AuditStatus, colorize
from strato.services.s3.domains.security.checks import S3SecurityResult, S3SecurityScanType


class S3SecurityView:
    @classmethod
    def get_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        base_headers = ["Account ID", "Bucket Name", "Region", "Creation Date"]
        status_headers = ["Status", "Findings"]

        if check_type == S3SecurityScanType.ALL:
            return base_headers + status_headers

        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = S3SecurityScanType.ALL) -> list[str]:
        base_headers = ["Account ID", "Bucket Name", "Region", "Creation Date"]
        status_headers = ["Status", "Findings"]

        dummy_result = S3SecurityResult(
            resource_arn="", resource_name="", region="", account_id="", check_type=check_type
        )
        dynamic_headers = [col_name for col_name, _, _ in cls._get_dynamic_columns(dummy_result)]

        return base_headers + dynamic_headers + status_headers

    @classmethod
    def format_row(cls, result: S3SecurityResult) -> list[str]:
        date_str = result.creation_date.strftime("%Y-%m-%d") if result.creation_date else "Unknown"
        row = [result.account_id, result.resource_name, result.region, date_str]

        if result.check_type != S3SecurityScanType.ALL:
            dynamic_cols = cls._get_dynamic_columns(result)
            for _, _, render_func in dynamic_cols:
                 row.append(render_func())

        row.append(cls._render_status(result.status))
        row.append(cls._render_findings(result.findings))

        return row

    @classmethod
    def format_csv_row(cls, result: S3SecurityResult) -> list[str]:
        date_str = result.creation_date.isoformat() if result.creation_date else "Unknown"
        row = [result.account_id, result.resource_name, result.region, date_str]

        dynamic_cols = cls._get_dynamic_columns(result)
        for _, raw_val, _ in dynamic_cols:
            if isinstance(raw_val, bool):
                row.append("Yes" if raw_val else "No")
            else:
                row.append(str(raw_val))

        row.append(result.status)
        row.append("; ".join(result.findings))
        return row

    @classmethod
    def _render_status(cls, status: str) -> str:
        status_color_map = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim white",
            "PASS": "green",
        }
        color = status_color_map.get(status, "white")
        return f"[{color}]{status}[/{color}]"

    @classmethod
    def _render_findings(cls, findings: list[str]) -> str:
        return ", ".join(findings) if findings else "-"

    @classmethod
    def _get_dynamic_columns(cls, r: S3SecurityResult) -> list[tuple[str, Any, Any]]:
        columns = []
        is_all = r.check_type == S3SecurityScanType.ALL

        if is_all or r.check_type == S3SecurityScanType.PUBLIC_ACCESS:
            columns.append(("Public Access Block", r.public_access_block_status, lambda: cls._render_bool(r.public_access_block_status, invert=False, true_text="Blocked", false_text="OPEN")))

        if is_all or r.check_type == S3SecurityScanType.POLICY:
            columns.append(("Policy Access", r.policy_access, lambda: cls._render_policy(r.policy_access)))
            columns.append(("SSL Enforced", r.ssl_enforced, lambda: cls._render_bool(r.ssl_enforced)))

        if is_all or r.check_type == S3SecurityScanType.ENCRYPTION:
            columns.append(("Encryption", r.encryption, lambda: cls._render_encryption(r.encryption)))
            columns.append(("SSE-C", r.sse_c, lambda: cls._render_bool(r.sse_c, true_text="Blocked", false_text="Allowed")))

        if is_all or r.check_type == S3SecurityScanType.ACLS:
            columns.append(("ACL Status", r.acl_status, lambda: cls._render_acl(r.acl_status, r.log_target)))
            columns.append(("Log Target", r.log_target, lambda: "Yes" if r.log_target else "No"))

        if is_all or r.check_type == S3SecurityScanType.VERSIONING:
            columns.append(("Versioning", r.versioning, lambda: cls._render_simple_status(r.versioning)))
            columns.append(("MFA Delete", r.mfa_delete, lambda: cls._render_simple_status(r.mfa_delete)))

        if is_all or r.check_type == S3SecurityScanType.OBJECT_LOCK:
            columns.append(("Object Lock", r.object_lock, lambda: cls._render_simple_status(r.object_lock)))

        if is_all or r.check_type == S3SecurityScanType.NAME_PREDICTABILITY:
            columns.append(("Name Predictability", r.name_predictability, lambda: cls._render_predictability(r.name_predictability)))

        if is_all or r.check_type == S3SecurityScanType.WEBSITE_HOSTING:
            columns.append(("Website Hosting", r.website_hosting, lambda: cls._render_bool(not r.website_hosting, true_text="Disabled", false_text="Enabled")))

        return columns

    @staticmethod
    def _render_bool(value: bool, invert=False, true_text="Yes", false_text="No") -> str:
        is_safe = not value if invert else value
        color = AuditStatus.PASS if is_safe else AuditStatus.FAIL
        text = true_text if value else false_text
        return colorize(text, color)

    @staticmethod
    def _render_simple_status(value: str) -> str:
        color = AuditStatus.PASS if value == "Enabled" else AuditStatus.WARN
        return colorize(value, color)

    @staticmethod
    def _render_encryption(val: str) -> str:
        if val != "None":
            return colorize(val, AuditStatus.PASS)
        return colorize("Missing", AuditStatus.WARN)

    @staticmethod
    def _render_policy(val: str) -> str:
        if val == "Private":
            return colorize(val, AuditStatus.PASS)
        if val == "Potentially Public":
            return colorize(val, AuditStatus.WARN)
        return colorize(val, AuditStatus.FAIL)

    @staticmethod
    def _render_acl(status: str, is_log_target: bool) -> str:
        if status == "Disabled":
            return colorize("Disabled", AuditStatus.PASS)
        text = "Enabled (Logs)" if is_log_target else "Enabled"
        color = AuditStatus.WARN if is_log_target else AuditStatus.FAIL
        return colorize(text, color)

    @staticmethod
    def _render_predictability(val: str) -> str:
        if val == "LOW":
            return colorize(val, AuditStatus.PASS)
        return colorize(val, AuditStatus.WARN)
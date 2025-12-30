import typer

from strato.core.runner import run_scan
from strato.services.s3.domains.security.checks import (
    S3SecurityScanner,
    S3SecurityScanType,
)
from strato.services.s3.domains.security.views import S3SecurityView

app = typer.Typer(help="S3 Security Audits")


def create_scan_command(target_scan_type: S3SecurityScanType, command_help_text: str):
    """
    Factory function to generate CLI commands dynamically.
    """

    def command(
        verbose: bool = False,
        json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
        csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
        failures_only: bool = typer.Option(
            False, "--failures-only", help="Only display resources with risks"
        ),
        org_role: str = typer.Option(
            None, "--org-role", help="IAM role to assume for multi-account scan"
        ),
    ):
        scan_code = run_scan(
            scanner_cls=S3SecurityScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            failures_only=failures_only,
            org_role=org_role,
            view_class=S3SecurityView,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    S3SecurityScanType.ALL: "Run ALL S3 Security checks",
    S3SecurityScanType.ENCRYPTION: "Scan for Encryption configuration",
    S3SecurityScanType.PUBLIC_ACCESS: "Scan for Public Access Block configuration",
    S3SecurityScanType.POLICY: "Scan for Bucket Policy compliance",
    S3SecurityScanType.ACLS: "Scan for Legacy ACL usage and Log Delivery compliance",
    S3SecurityScanType.VERSIONING: "Scan for Versioning and MFA Delete configuration",
    S3SecurityScanType.OBJECT_LOCK: "Scan for Object Lock configuration",
    S3SecurityScanType.NAME_PREDICTABILITY: "Scan for Predictable Bucket Names",
    S3SecurityScanType.WEBSITE_HOSTING: "Scan for Static Website Hosting configuration",
}

CMD_NAME_MAP = {
    S3SecurityScanType.NAME_PREDICTABILITY: "naming",
    S3SecurityScanType.WEBSITE_HOSTING: "website",
}

for scan_type in S3SecurityScanType:
    cmd_name = CMD_NAME_MAP.get(scan_type, scan_type.value.replace("_", "-"))
    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")

    app.command(cmd_name)(create_scan_command(scan_type, help_text))

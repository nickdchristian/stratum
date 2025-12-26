import typer

from strato.core.runner import run_scan
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanner,
    S3SecurityScanType,
)
from strato.services.s3.domains.security.views import S3SecurityView

app = typer.Typer(help="S3 Security Audits")


@app.command("all")
def security_scan_all(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Only display resources with risks"
    ),
    org_role: str = typer.Option(
        None, "--org-role", help="IAM role to assume for multi-account scan"
    ),
):
    """Run ALL S3 Security checks."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ALL,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("encryption")
def encryption_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Encryption configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ENCRYPTION,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("public-access")
def public_access_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Public Access Block configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.PUBLIC_ACCESS,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("policy")
def policy_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Bucket Policy compliance (SSL & Public permissions)."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.POLICY,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("acls")
def acl_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Legacy ACL usage and Log Delivery compliance."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ACLS,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("versioning")
def versioning_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Versioning and MFA Delete configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.VERSIONING,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("object-lock")
def object_lock_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Object Lock configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.OBJECT_LOCK,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("naming")
def name_predictability_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Predictable Bucket Names (Entropy check)."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.NAME_PREDICTABILITY,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )


@app.command("website")
def website_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
    org_role: str = typer.Option(None, "--org-role"),
):
    """Scan for Static Website Hosting configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.WEBSITE_HOSTING,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
        org_role,
        view_class=S3SecurityView,
    )
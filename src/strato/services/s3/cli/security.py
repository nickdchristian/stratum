import typer

from strato.core.runner import run_scan
from strato.services.s3.domains.security import (
    S3SecurityResult,
    S3SecurityScanner,
    S3SecurityScanType,
)

app = typer.Typer(help="S3 Security Audits")


@app.command("all")
def security_scan_all(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found (for CI/CD)"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output raw JSON (silences spinner)"
    ),
    csv_output: bool = typer.Option(
        False, "--csv", help="Output CSV (silences spinner)"
    ),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Only display resources with risks"
    ),
):
    """Run ALL S3 Security checks (Encryption and Public Access)."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ALL,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("encryption")
def encryption_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Show failures only"
    ),
):
    """Scan ONLY for default encryption configuration."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ENCRYPTION,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("public-access")
def public_access_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(
        False, "--fail-on-risk", help="Exit code 1 if risks found"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    failures_only: bool = typer.Option(
        False, "--failures-only", help="Show failures only"
    ),
):
    """Scan ONLY for public access blocks."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.PUBLIC_ACCESS,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("acls")
def acl_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
):
    """Scan ONLY for Legacy ACL usage and Log Delivery compliance."""
    run_scan(
        S3SecurityScanner,
        S3SecurityResult,
        S3SecurityScanType.ACLS,
        verbose,
        fail_on_risk,
        json_output,
        csv_output,
        failures_only,
    )


@app.command("versioning")
def versioning_scan(
    verbose: bool = False,
    fail_on_risk: bool = typer.Option(False, "--fail-on-risk"),
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    failures_only: bool = typer.Option(False, "--failures-only"),
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
    )

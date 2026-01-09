import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.rds.domains.reserved.checks import (
    RDSReservedInstanceScanner,
    RDSReservedScanType,
)
from strato.services.rds.domains.reserved.views import RDSReservedInstanceView

app = typer.Typer(help="RDS Reserved Instance Contracts")
console_err = Console(stderr=True)


@app.command("scan")
def scan(
    verbose: bool = False,
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
    region: str = typer.Option(None, "--region", help="Specific AWS Region to scan"),
    org_role: str = typer.Option(
        None, "--org-role", help="IAM role to assume for multi-account scan"
    ),
):
    """
    Scan for Purchased Reserved Instances (Active Contracts).
    """
    if not (json_output or csv_output):
        console_err.print(
            "\n[bold red]Error:[/bold red] RI data requires structured output."
        )
        console_err.print(
            "Please specify: [green]--json[/green] or [green]--csv[/green]\n"
        )
        raise typer.Exit(1)

    scan_code = run_scan(
        scanner_cls=RDSReservedInstanceScanner,
        check_type=RDSReservedScanType.RESERVED_INSTANCES,
        verbose=verbose,
        json_output=json_output,
        csv_output=csv_output,
        failures_only=False,
        org_role=org_role,
        view_class=RDSReservedInstanceView,
        region=region,
    )

    if scan_code != 0:
        raise typer.Exit(scan_code)

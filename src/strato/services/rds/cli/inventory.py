import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.rds.domains.inventory.checks import (
    RDSInventoryScanner,
    RDSInventoryScanType,
)
from strato.services.rds.domains.inventory.views import RDSInventoryView

app = typer.Typer(help="RDS Inventory & Audit")
console_err = Console(stderr=True)


def create_scan_command(target_scan_type: RDSInventoryScanType, command_help_text: str):
    """
    Factory function to generate CLI commands dynamically.
    """

    def command(
        verbose: bool = False,
        json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
        csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
        region: str = typer.Option(
            None, "--region", help="Specific AWS Region to scan (e.g. us-east-1)"
        ),
        org_role: str = typer.Option(
            None, "--org-role", help="IAM role to assume for multi-account scan"
        ),
    ):
        if not (json_output or csv_output):
            console_err.print(
                "\n[bold red]"
                "Error:"
                "[/bold red] Inventory data is too wide for table output."
            )
            console_err.print(
                "Please specify a structured format: "
                "[green]--json[/green] or [green]--csv[/green]\n"
            )
            raise typer.Exit(1)

        scan_code = run_scan(
            scanner_cls=RDSInventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            failures_only=False,
            org_role=org_role,
            view_class=RDSInventoryView,
            region=region,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    RDSInventoryScanType.INVENTORY: "Gather a comprehensive inventory of RDS Instances",
}

CMD_NAME_MAP = {
    RDSInventoryScanType.INVENTORY: "scan",
}

for scan_type in RDSInventoryScanType:
    default_name = scan_type.value.replace("_", "-").lower()
    cmd_name = CMD_NAME_MAP.get(scan_type, default_name)

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")

    app.command(cmd_name)(create_scan_command(scan_type, help_text))

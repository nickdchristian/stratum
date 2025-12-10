import csv
import sys

from rich.console import Console
from rich.table import Table

from .models import AuditResult

console = Console()


class AuditPresenter:
    """
    Handles the presentation layer.
    Decouples the logic of *how* to display data from the data itself.
    """

    def __init__(
        self,
        results: list[AuditResult],
        result_type: type[AuditResult],
        check_type: str = "ALL",
    ):
        self.results = results
        self.result_type = result_type
        self.check_type = check_type

    def print_json(self):
        """Dumps full result objects to stdout as JSON."""
        console.print_json(data=[r.to_dict() for r in self.results])

    def print_csv(self):
        """Writes CSV data to stdout."""
        writer = csv.writer(sys.stdout)

        if hasattr(self.result_type, "get_csv_headers"):
            headers = self.result_type.get_csv_headers(self.check_type)
        else:
            headers = self.result_type.get_headers(self.check_type)

        writer.writerow(headers)

        for result in self.results:
            writer.writerow(result.get_csv_row())

    def print_table(self, title: str):
        """Renders a formatted Rich table to the console."""
        table = Table(title=title)

        headers = self.result_type.get_headers(self.check_type)
        for header in headers:
            table.add_column(header)

        for result in self.results:
            table.add_row(*result.get_table_row())

        console.print(table)
        self._print_summary()

    def _print_summary(self):
        """Prints the final pass/fail summary below the table."""
        risk_count = sum(len(result.risk_reasons) for result in self.results)
        if risk_count > 0:
            console.print(f"\n[bold red]Found {risk_count} risks.[/bold red]")
        else:
            console.print("\n[bold green]All checks passed.[/bold green]")

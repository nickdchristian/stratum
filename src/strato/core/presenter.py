import csv
import sys
from typing import Protocol, Any

from rich.console import Console
from rich.table import Table

from .models import AuditResult

console = Console()


class ViewProtocol(Protocol):
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def format_row(cls, result: Any) -> list[str]: ...

    @classmethod
    def format_csv_row(cls, result: Any) -> list[str]: ...


class AuditPresenter:
    def __init__(
            self,
            results: list[AuditResult],
            result_type: type[AuditResult],
            check_type: str = "ALL",
            view_class: type[ViewProtocol] | None = None,
    ):
        self.results = results
        self.result_type = result_type
        self.check_type = check_type
        self.view_class = view_class

    def print_json(self):
        console.print_json(data=[r.to_dict() for r in self.results])

    def print_csv(self):
        writer = csv.writer(sys.stdout)

        if self.view_class and hasattr(self.view_class, "get_csv_headers"):
            headers = self.view_class.get_csv_headers(self.check_type)
        elif self.view_class:
            headers = self.view_class.get_headers(self.check_type)
        elif hasattr(self.result_type, "get_csv_headers"):
            headers = self.result_type.get_csv_headers(self.check_type)
        else:
            headers = ["Account", "Resource", "Region", "Status", "Findings"]

        writer.writerow(headers)

        for result in self.results:
            if self.view_class:
                row = self.view_class.format_csv_row(result)
            elif hasattr(result, "get_csv_row"):
                row = result.get_csv_row()
            else:
                row = [result.account_id, result.resource_name, result.region, result.status, str(result.findings)]

            writer.writerow(row)

    def print_table(self, title: str):
        table = Table(title=title)

        if self.view_class:
            headers = self.view_class.get_headers(self.check_type)
        elif hasattr(self.result_type, "get_headers"):
            headers = self.result_type.get_headers(self.check_type)
        else:
            headers = ["Account", "Resource", "Region", "Status", "Findings"]

        for header in headers:
            table.add_column(header)

        for result in self.results:
            if self.view_class:
                table.add_row(*self.view_class.format_row(result))
            elif hasattr(result, "get_table_row"):
                table.add_row(*result.get_table_row())
            else:
                table.add_row(result.account_id, result.resource_name, result.status)

        console.print(table)
        self._print_summary()

    def _print_summary(self):
        violation_count = sum(
            len(result.findings) for result in self.results if result.is_violation
        )
        if violation_count > 0:
            console.print(f"\n[bold red]Found {violation_count} violations.[/bold red]")
        else:
            console.print("\n[bold green]All checks passed.[/bold green]")
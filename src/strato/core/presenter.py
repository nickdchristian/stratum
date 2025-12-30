import csv
import sys
from enum import StrEnum
from typing import Any, Protocol

from rich.console import Console
from rich.table import Table

from strato.core.models import AuditResult

console_out = Console(file=sys.stdout)
console_err = Console(stderr=True)


class AuditStatus(StrEnum):
    PASS = "green"
    FAIL = "red"
    WARN = "yellow"
    INFO = "blue"


def colorize(text: str, status: AuditStatus) -> str:
    return f"[{status}]{text}[/{status}]"


class ViewProtocol(Protocol):
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def format_row(cls, result: Any) -> list[str]: ...

    @classmethod
    def format_csv_row(cls, result: Any) -> list[str]: ...


class GenericView:
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return ["Account ID", "Resource", "Region", "Status", "Findings"]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return cls.get_headers(check_type)

    @classmethod
    def format_row(cls, result: AuditResult) -> list[str]:
        status_color_map = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim white",
            "PASS": "green",
        }
        color = status_color_map.get(result.status, "white")
        status_render = f"[{color}]{result.status}[/{color}]"
        findings_render = ", ".join(result.findings) if result.findings else "-"

        return [
            result.account_id,
            result.resource_name,
            result.region,
            status_render,
            findings_render,
        ]

    @classmethod
    def format_csv_row(cls, result: AuditResult) -> list[str]:
        return [
            result.account_id,
            result.resource_name,
            result.region,
            result.status,
            "; ".join(result.findings),
        ]


class AuditPresenter:
    def __init__(
        self,
        results: list[AuditResult],
        check_type: str = "ALL",
        view_class: type[ViewProtocol] = GenericView,
    ):
        self.results = results
        self.check_type = check_type
        self.view_class = view_class or GenericView

    def print_json(self):
        console_out.print_json(data=[r.to_dict() for r in self.results])

    def print_csv(self):
        writer = csv.writer(sys.stdout)
        headers = self.view_class.get_csv_headers(self.check_type)
        writer.writerow(headers)

        for result in self.results:
            writer.writerow(self.view_class.format_csv_row(result))

    def print_table(self, title: str):
        table = Table(title=title, show_lines=True)
        headers = self.view_class.get_headers(self.check_type)

        for header in headers:
            table.add_column(header)

        for result in self.results:
            table.add_row(*self.view_class.format_row(result))

        console_out.print(table)
        self._print_summary()

    def _print_summary(self):
        violation_count = sum(
            len(result.findings) for result in self.results if result.is_violation
        )
        if violation_count > 0:
            console_err.print(
                f"\n[bold red]Found {violation_count} violations.[/bold red]"
            )
        else:
            console_err.print("\n[bold green]All checks passed.[/bold green]")

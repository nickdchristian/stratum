from abc import ABC, abstractmethod
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, TypeVar

import boto3
from rich.console import Console

console_err = Console(stderr=True)


class ObservationLevel(IntEnum):
    """
    Standardized scoring levels for audit findings across all Well-Architected pillars.

    Use these levels to weigh the impact of a finding regardless of the category:

    * **CRITICAL (100):** Existential threat to the workload or business.
    * **HIGH (50):** Significant risk or violation of core architecture standards.
    * **MEDIUM (20):** Deviation from best practices. Not immediate, but technical debt.
    * **LOW (5):** Hygiene, organization, or minor optimization opportunities.
    * **INFO (1):** Contextual data. Not a defect, but useful for the report.
    * **PASS (0):** The resource fully complies with the check requirements.
    """

    CRITICAL = 100
    HIGH = 50
    MEDIUM = 20
    LOW = 5
    INFO = 1
    PASS = 0


@dataclass
class AuditResult:
    """Base data structure for any resource audit."""

    resource_arn: str
    resource_name: str
    region: str
    account_id: str = "Unknown"
    status_score: int = 0
    findings: list[str] = field(default_factory=list)

    @property
    def is_violation(self) -> bool:
        return self.status_score >= ObservationLevel.LOW

    @property
    def status(self) -> str:
        if self.status_score >= ObservationLevel.CRITICAL:
            return "CRITICAL"
        if self.status_score >= ObservationLevel.HIGH:
            return "HIGH"
        if self.status_score >= ObservationLevel.MEDIUM:
            return "MEDIUM"
        if self.status_score >= ObservationLevel.LOW:
            return "LOW"
        if self.status_score == ObservationLevel.INFO:
            return "INFO"
        return "PASS"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


T = TypeVar("T", bound=AuditResult)


class BaseScanner[AuditResultType: AuditResult](ABC):
    """Abstract base class for all resource scanners."""

    is_global_service: bool = False

    def __init__(
        self,
        check_type: str = "ALL",
        session: boto3.Session = None,
        account_id: str = "Unknown",
    ):
        self.check_type = check_type
        self.session = session or boto3.Session()
        self.account_id = account_id

    @property
    @abstractmethod
    def service_name(self) -> str:
        pass

    @abstractmethod
    def fetch_resources(self) -> Iterable[Any]:
        pass

    @abstractmethod
    def analyze_resource(self, resource: Any) -> T:
        pass

    def scan(self, silent: bool = False) -> list[T]:
        """
        Orchestrates the fetching and analyzing of resources.
        Uses console_err for status to avoid polluting stdout.
        """
        results = []
        resource_stream = self.fetch_resources()

        def process_stream():
            with ThreadPoolExecutor(max_workers=20) as executor:
                results.extend(executor.map(self.analyze_resource, resource_stream))

        if silent:
            process_stream()
        else:
            with console_err.status(
                f"[bold yellow]Scanning {self.service_name} resources...",
                spinner="dots",
            ):
                process_stream()

        return results

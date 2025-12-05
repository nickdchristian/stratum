from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import List, Any, Generic, TypeVar, Iterable

from rich.console import Console

from stratum.core.models import AuditResult

T = TypeVar("T", bound=AuditResult)
console = Console(stderr=True)


class BaseScanner(ABC, Generic[T]):
    """Abstract base class for all resource scanners."""

    def __init__(self, check_type: str = "ALL"):
        self.check_type = check_type

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Returns the display name of the service (e.g., 'S3 Security')."""
        pass

    @abstractmethod
    def fetch_resources(self) -> Iterable[Any]:
        """Yields raw resource objects (dicts, boto3 objects) to be analyzed."""
        pass

    @abstractmethod
    def analyze_resource(self, resource: Any) -> T:
        """Transforms a raw resource into a typed AuditResult."""
        pass

    def scan(self, silent: bool = False) -> List[T]:
        """Orchestrates the fetching and analyzing of resources."""
        results = []
        # fetch_resources is called before threading to gather the initial iterator
        resource_stream = self.fetch_resources()

        def process_stream():
            # Adjust if encountering ThrottlingExceptions.
            with ThreadPoolExecutor(max_workers=20) as executor:
                results.extend(executor.map(self.analyze_resource, resource_stream))

        if silent:
            process_stream()
        else:
            with console.status(
                f"[bold yellow]Scanning {self.service_name} resources...",
                spinner="dots",
            ):
                process_stream()

        return results

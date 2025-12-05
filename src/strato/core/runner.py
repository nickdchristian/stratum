import logging
import sys

from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console

from strato.core.models import AuditResult
from strato.core.presenter import AuditPresenter
from strato.core.scanner import BaseScanner

console = Console()


def setup_logging(verbose: bool):
    """Configures global logging. Default is WARNING to keep CLI output clean."""
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def run_scan(
    scanner_cls: type[BaseScanner],
    result_cls: type[AuditResult],
    check_type: str,
    verbose: bool,
    fail_on_risk: bool,
    json_output: bool,
    csv_output: bool,
    failures_only: bool,
):
    """
    Universal Runner Entrypoint.

    Orchestrates the lifecycle of a scan:
    1. Setup Logging
    2. Instantiate Scanner
    3. Execute Scan (handling AWS Auth errors)
    4. Filter Results
    5. Present Data (JSON/CSV/Table)
    6. Handle Exit Codes
    """
    setup_logging(verbose)
    scanner = scanner_cls(check_type=check_type)

    try:
        # Silent mode is enabled for structured output (JSON/CSV) so the
        # loading spinner doesn't corrupt the output stream.
        results = scanner.scan(silent=(json_output or csv_output))
    except NoCredentialsError:
        console.print(
            "[bold red]Error:[/bold red] No AWS credentials found."
            " Please configure your environment."
        )
        sys.exit(1)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        # Handle common auth issues specifically for better UX
        if error_code in [
            "InvalidClientTokenId",
            "SignatureDoesNotMatch",
            "AuthFailure",
            "ExpiredToken",
        ]:
            console.print(
                "[bold red]Error:[/bold red] Invalid AWS credentials. "
                "Please check your keys/token."
            )
        else:
            console.print(f"[bold red]Error:[/bold red] AWS API failed: {error_code}")
        sys.exit(1)

    if failures_only:
        results = [result for result in results if result.has_risk]

    presenter = AuditPresenter(results, result_type=result_cls, check_type=check_type)

    if json_output:
        presenter.print_json()
    elif csv_output:
        presenter.print_csv()
    else:
        title_suffix = " [Failures Only]" if failures_only else ""
        presenter.print_table(title=f"{scanner.service_name}{title_suffix}")

    if fail_on_risk and any(result.has_risk for result in results):
        sys.exit(1)

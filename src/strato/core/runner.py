import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console

from strato.core.models import AuditResult
from strato.core.presenter import AuditPresenter
from strato.core.scanner import BaseScanner

console = Console()


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.ERROR
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def get_org_accounts() -> list[dict]:
    org_client = boto3.client("organizations")
    accounts = []
    paginator = org_client.get_paginator("list_accounts")

    try:
        for page in paginator.paginate():
            for acc in page["Accounts"]:
                if acc["Status"] == "ACTIVE":
                    accounts.append({"Id": acc["Id"], "Name": acc["Name"]})
    except ClientError as e:
        console.print(f"[bold red]Error listing accounts:[/bold red] {e}")
        sys.exit(1)

    return accounts


def assume_role_session(account_id: str, role_name: str) -> boto3.Session | None:
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="StratoAuditSession"
        )
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError:
        return None


def scan_single_account(
    account: dict, role_name: str, scanner_cls: type[BaseScanner], check_type: str
) -> tuple[list[AuditResult], str | None]:
    account_id = account["Id"]
    account_name = account["Name"]
    target_session = assume_role_session(account_id, role_name)

    if not target_session:
        return [], f"Access Denied: {account_id} ({account_name})"

    scanner = scanner_cls(
        check_type=check_type, session=target_session, account_id=account_id
    )

    try:
        return scanner.scan(silent=True), None
    except Exception as e:
        return [], f"Scan Error: {account_id} - {str(e)}"


def run_scan(
    scanner_cls: type[BaseScanner],
    result_cls: type[AuditResult],
    check_type: str,
    verbose: bool,
    fail_on_finding: bool,
    json_output: bool,
    csv_output: bool,
    failures_only: bool,
    org_role: str = None,
    view_class: Any = None,
):
    setup_logging(verbose)
    all_results = []
    skipped_accounts = []

    if org_role:
        accounts = get_org_accounts()
        console.print(
            f"[bold blue]Scanning {len(accounts)} accounts "
            f"with role '{org_role}'...[/bold blue]"
        )

        with console.status(
            "[bold yellow]Running Multi-Account Scan...", spinner="dots"
        ):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(
                        scan_single_account, acc, org_role, scanner_cls, check_type
                    ): acc
                    for acc in accounts
                }

                for future in as_completed(futures):
                    results, error = future.result()
                    if error:
                        skipped_accounts.append(error)
                    else:
                        all_results.extend(results)

        if skipped_accounts:
            console.print(
                f"\n[bold yellow]Skipped "
                f"{len(skipped_accounts)} accounts:[/bold yellow]"
            )
            for skip_msg in skipped_accounts:
                console.print(f"  • {skip_msg}", style="yellow")
            console.print("")

    else:
        sts = boto3.client("sts")
        try:
            current_account = sts.get_caller_identity()["Account"]
        except (ClientError, NoCredentialsError):
            current_account = "Unknown"

        scanner = scanner_cls(check_type=check_type, account_id=current_account)

        try:
            all_results = scanner.scan(silent=(json_output or csv_output))
        except NoCredentialsError:
            console.print(
                "[bold red]Error:[/bold red] No AWS credentials found. "
                "Please configure your environment."
            )
            sys.exit(1)
        except ClientError as e:
            console.print(f"[bold red]Error:[/bold red] AWS API failed: {e}")
            sys.exit(1)

    if failures_only:
        all_results = [result for result in all_results if result.is_violation]

    presenter = AuditPresenter(
        all_results,
        result_type=result_cls,
        check_type=check_type,
        view_class=view_class
    )

    if json_output:
        presenter.print_json()
    elif csv_output:
        presenter.print_csv()
    else:
        if all_results:
            title_suffix = " [Failures Only]" if failures_only else ""
            title_prefix = "Organization " if org_role else ""
            presenter.print_table(
                title=f"{title_prefix}{scanner_cls(check_type).service_name}{title_suffix}"
            )
        else:
            console.print("[bold blue]No Results Found[/bold blue]")

    if fail_on_finding and any(result.is_violation for result in all_results):
        sys.exit(1)
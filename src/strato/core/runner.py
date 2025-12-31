import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError
from rich.console import Console

from strato.core.models import AuditResult, BaseScanner
from strato.core.presenter import AuditPresenter

console_err = Console(stderr=True)


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
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
        console_err.print(f"[bold red]Error listing accounts:[/bold red] {e}")
        sys.exit(1)
    except NoRegionError:
        console_err.print(
            "[bold red]Error:[/bold red] No AWS region specified. "
            "Please set "
            "[green]AWS_DEFAULT_REGION[/green] or use the "
            "[green]--region[/green] flag."
        )
        sys.exit(1)

    return accounts


def assume_role_session(
    account_id: str, role_name: str, region: str | None = None
) -> boto3.Session | None:
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
            region_name=region,
        )
    except ClientError:
        return None
    except NoRegionError:
        return None


def scan_single_account(
    account_id: str,
    account_name: str,
    role_name: str | None,
    scanner_cls: type[BaseScanner],
    check_type: str,
    region: str | None = None,
) -> tuple[list[AuditResult], str | None]:
    try:
        if role_name:
            session = assume_role_session(account_id, role_name, region)
            if not session:
                return [], f"Access Denied: {account_id} ({account_name})"
        else:
            session = boto3.Session(region_name=region)

        scanner = scanner_cls(
            check_type=check_type, session=session, account_id=account_id
        )
        return scanner.scan(silent=True), None

    except NoRegionError:
        return [], f"Configuration Error: No Region specified for {account_id}"
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        return [], f"AWS Error: {account_id} - {error_code}: {e}"
    except Exception as e:
        return [], f"Unexpected Error: {account_id} - {str(e)}"


def _execute_multi_account_scan(
    scanner_cls: type[BaseScanner],
    check_type: str,
    org_role: str,
    region: str | None = None,
) -> list[AuditResult]:
    if not scanner_cls.is_global_service:
        if not region and not boto3.Session().region_name:
            console_err.print(
                "[bold red]"
                "Configuration Error:"
                "[/bold red] You must specify a region for multi-account scans.\n"
                "Use the "
                "[green]--region"
                "[/green] flag or set the "
                "[green]AWS_DEFAULT_REGION[/green] environment variable."
            )
            sys.exit(1)

    if scanner_cls.is_global_service and not region:
        region = "us-east-1"

    accounts = get_org_accounts()
    all_results = []
    skipped = []

    console_err.print(
        f"[bold blue]Scanning {len(accounts)} accounts "
        f"with role '{org_role}'...[/bold blue]"
    )

    with console_err.status(
        "[bold yellow]Running Multi-Account Scan...", spinner="dots"
    ):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(
                    scan_single_account,
                    acc["Id"],
                    acc["Name"],
                    org_role,
                    scanner_cls,
                    check_type,
                    region,
                ): acc
                for acc in accounts
            }

            for future in as_completed(futures):
                results, error = future.result()
                if error:
                    skipped.append(error)
                else:
                    all_results.extend(results)

    if skipped:
        console_err.print(
            f"\n[bold yellow]Skipped {len(skipped)} accounts:[/bold yellow]"
        )
        for msg in skipped:
            console_err.print(f"  • {msg}", style="yellow")
        console_err.print("")

    return all_results


def run_scan(
    scanner_cls: type[BaseScanner],
    check_type: str,
    verbose: bool,
    json_output: bool,
    csv_output: bool,
    failures_only: bool,
    org_role: str = None,
    view_class: Any = None,
    region: str | None = None,
):
    setup_logging(verbose)

    if org_role:
        all_results = _execute_multi_account_scan(
            scanner_cls, check_type, org_role, region
        )
    else:
        silent_mode = json_output or csv_output
        sts = boto3.client("sts")

        current_account = "Unknown"

        try:
            current_account = sts.get_caller_identity()["Account"]
        except (ClientError, NoCredentialsError):
            current_account = "Unknown"
        except NoRegionError:
            pass

        try:
            if scanner_cls.is_global_service and not region:
                region = "us-east-1"

            session = boto3.Session(region_name=region)

            if not scanner_cls.is_global_service and not session.region_name:
                raise NoRegionError()

            scanner = scanner_cls(
                check_type=check_type, session=session, account_id=current_account
            )
            all_results = scanner.scan(silent=silent_mode)

        except NoRegionError:
            console_err.print(
                "\n[bold red]Configuration Error:[/bold red] No AWS region specified."
            )
            console_err.print(
                "Please provide a region using the "
                "[green]--region"
                "[/green] flag or set the "
                "[green]AWS_DEFAULT_REGION[/green] environment variable.\n"
            )
            return 1
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            console_err.print(
                f"[bold red]AWS Error:[/bold red] {current_account} - {error_code}: {e}"
            )
            return 1
        except Exception as e:
            console_err.print(
                f"[bold red]Unexpected Error:[/bold red] {current_account} - {e}"
            )
            return 1

    if failures_only:
        all_results = [result for result in all_results if result.is_violation]

    presenter = AuditPresenter(
        all_results,
        check_type=check_type,
        view_class=view_class,
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
            console_err.print("[bold blue]No Results Found[/bold blue]")

    if any(result.is_violation for result in all_results):
        return 1

    return 0

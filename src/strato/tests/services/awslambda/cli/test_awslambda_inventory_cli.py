from unittest import mock

from typer.testing import CliRunner

import strato.services.awslambda.cli.inventory as inventory_module
from strato.services.awslambda.cli.inventory import app
from strato.services.awslambda.domains.inventory.checks import LambdaScanType

runner = CliRunner(mix_stderr=False)


def get_scan_command_name():
    """
    Dynamically retrieves the command name
    to handle potential Typer registration oddities.
    """
    if not app.registered_commands:
        return "scan"
    return app.registered_commands[0].name


def invoke_scan_command(args):
    """
    Helper to robustly invoke the command.
    It attempts standard invocation first, then fallbacks to root invocation
    if Typer treats the app itself as the single command.
    """
    cmd_name = get_scan_command_name()

    full_args = [cmd_name] + args
    result = runner.invoke(app, full_args)

    if (
        result.exit_code == 2
        and f"unexpected extra argument ({cmd_name})" in result.stderr
    ):
        return runner.invoke(app, args)

    return result


def test_app_structure():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_success_json(mock_run_scan):
    mock_run_scan.return_value = 0

    result = invoke_scan_command(["--json", "--region", "us-east-1"])

    debug_info = f"\nStdout: {result.stdout}\nStderr: {result.stderr}"
    assert result.exit_code == 0, (
        f"Expected Exit 0, got {result.exit_code}. {debug_info}"
    )

    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == LambdaScanType.INVENTORY
    assert kwargs["json_output"] is True
    assert kwargs["region"] == "us-east-1"


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_requires_format(mock_run_scan):
    # Pass empty args to trigger the format check failure inside the command
    result = invoke_scan_command([])

    debug_info = f"\nStdout: {result.stdout}\nStderr: {result.stderr}"

    # Typer usage errors are 2; our custom 'missing format' error is 1.
    assert result.exit_code == 1, (
        f"Expected Exit 1, got {result.exit_code}. {debug_info}"
    )
    assert "Lambda inventory data is too wide" in (result.stderr + result.stdout)

    mock_run_scan.assert_not_called()


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_custom_role(mock_run_scan):
    mock_run_scan.return_value = 0

    result = invoke_scan_command(["--csv", "--org-role", "AuditRole"])

    debug_info = f"\nStdout: {result.stdout}\nStderr: {result.stderr}"
    assert result.exit_code == 0, (
        f"Expected Exit 0, got {result.exit_code}. {debug_info}"
    )

    args, kwargs = mock_run_scan.call_args
    assert kwargs["csv_output"] is True
    assert kwargs["org_role"] == "AuditRole"

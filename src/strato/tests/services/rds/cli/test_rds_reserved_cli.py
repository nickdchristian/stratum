from unittest import mock

from typer.testing import CliRunner

import strato.services.rds.cli.reserved as reserved_module
from strato.services.rds.cli.reserved import app
from strato.services.rds.domains.reserved.checks import RDSReservedScanType

runner = CliRunner(mix_stderr=False)


def get_scan_command_name():
    """
    Dynamically retrieves the command name to
    handle potential Typer registration oddities.
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


@mock.patch.object(reserved_module, "run_scan")
def test_reserved_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0

    result = invoke_scan_command(["--csv"])

    debug_info = f"\nStdout: {result.stdout}\nStderr: {result.stderr}"
    assert result.exit_code == 0, (
        f"Expected Exit 0, got {result.exit_code}. {debug_info}"
    )

    args, kwargs = mock_run_scan.call_args

    assert kwargs["check_type"] == RDSReservedScanType.RESERVED_INSTANCES
    assert kwargs["csv_output"] is True


@mock.patch.object(reserved_module, "run_scan")
def test_reserved_scan_requires_format(mock_run_scan):
    result = invoke_scan_command([])

    debug_info = f"\nStdout: {result.stdout}\nStderr: {result.stderr}"
    assert result.exit_code == 1, (
        f"Expected Exit 1, got {result.exit_code}. {debug_info}"
    )
    assert "RI data requires structured output" in (result.stderr + result.stdout)

    mock_run_scan.assert_not_called()

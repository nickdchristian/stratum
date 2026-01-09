from unittest import mock

from typer.testing import CliRunner

import strato.services.ec2.cli.reserved as reserved_module
from strato.services.ec2.cli.reserved import app
from strato.services.ec2.domains.reserved.checks import EC2ReservedScanType

runner = CliRunner(mix_stderr=False)


def get_scan_command_name():
    if not app.registered_commands:
        return "scan"
    return app.registered_commands[0].name


def invoke_scan_command(args):
    cmd_name = get_scan_command_name()
    full_args = [cmd_name] + args
    result = runner.invoke(app, full_args)

    # Handle Typer single-command app behavior
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

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == EC2ReservedScanType.RESERVED_INSTANCES
    assert kwargs["csv_output"] is True


@mock.patch.object(reserved_module, "run_scan")
def test_reserved_scan_requires_format(mock_run_scan):
    result = invoke_scan_command([])

    assert result.exit_code == 1
    assert "RI data requires structured output" in (result.stderr + result.stdout)
    mock_run_scan.assert_not_called()

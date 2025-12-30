from unittest import mock

from typer.testing import CliRunner

import strato.services.s3.cli.security as security_cli
from strato.services.s3.cli.security import app
from strato.services.s3.domains.security.checks import S3SecurityScanType

runner = CliRunner()


@mock.patch.object(security_cli, "run_scan")
def test_security_scan_all_defaults(mock_run_scan):
    """Pass with default args."""
    mock_run_scan.return_value = 0
    result = runner.invoke(app, ["all"])
    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == S3SecurityScanType.ALL
    assert kwargs["verbose"] is False
    assert kwargs["json_output"] is False


@mock.patch.object(security_cli, "run_scan")
def test_security_scan_custom_flags(mock_run_scan):
    """Pass with custom flags."""
    mock_run_scan.return_value = 0
    role_name = "audit-role-name"

    result = runner.invoke(
        app,
        [
            "encryption",
            "--verbose",
            "--json",
            "--org-role",
            role_name,
        ],
    )
    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == S3SecurityScanType.ENCRYPTION
    assert kwargs["verbose"] is True
    assert kwargs["json_output"] is True
    assert kwargs["org_role"] == role_name


def test_dynamic_command_mapping():
    """Verify command generation."""
    command_names = [c.name for c in app.registered_commands]
    assert "naming" in command_names
    assert "website" in command_names

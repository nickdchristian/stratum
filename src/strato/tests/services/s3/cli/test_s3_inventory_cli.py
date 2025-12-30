from unittest import mock

from typer.testing import CliRunner

import strato.services.s3.cli.inventory as inventory_cli
from strato.services.s3.cli.inventory import app
from strato.services.s3.domains.inventory.checks import S3InventoryScanType

runner = CliRunner(mix_stderr=False)


@mock.patch.object(inventory_cli, "run_scan")
def test_inventory_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0

    result = runner.invoke(app, ["scan", "--json"])

    assert result.exit_code == 0

    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == S3InventoryScanType.INVENTORY
    assert kwargs["verbose"] is False
    assert kwargs["json_output"] is True
    assert kwargs["csv_output"] is False


@mock.patch.object(inventory_cli, "run_scan")
def test_inventory_scan_requires_format(mock_run_scan):
    mock_run_scan.return_value = 0

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    output = result.stderr + result.stdout
    assert "Inventory data is too wide" in output


@mock.patch.object(inventory_cli, "run_scan")
def test_inventory_scan_custom_flags(mock_run_scan):
    mock_run_scan.return_value = 0

    result = runner.invoke(
        app, ["scan", "--csv", "--verbose", "--org-role", "audit-role"]
    )

    assert result.exit_code == 0

    args, kwargs = mock_run_scan.call_args
    assert kwargs["verbose"] is True
    assert kwargs["csv_output"] is True
    assert kwargs["org_role"] == "audit-role"


def test_dynamic_command_mapping():
    command_names = [c.name for c in app.registered_commands]
    assert "scan" in command_names

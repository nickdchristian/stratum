from unittest import mock

from typer.testing import CliRunner

import strato.services.ec2.cli.inventory as inventory_module
from strato.services.ec2.cli.inventory import app
from strato.services.ec2.domains.inventory.checks import EC2InventoryScanType

runner = CliRunner(mix_stderr=False)


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = runner.invoke(app, ["scan", "--json", "--region", "us-west-2"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args

    assert kwargs["check_type"] == EC2InventoryScanType.INVENTORY
    assert kwargs["json_output"] is True
    assert kwargs["region"] == "us-west-2"


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_requires_format(mock_run_scan):
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "Inventory data is too wide" in (result.stderr + result.stdout)

    mock_run_scan.assert_not_called()


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_custom_role(mock_run_scan):
    mock_run_scan.return_value = 0
    result = runner.invoke(
        app, ["scan", "--csv", "--org-role", "AuditRole", "--region", "us-east-1"]
    )
    assert result.exit_code == 0

    args, kwargs = mock_run_scan.call_args
    assert kwargs["org_role"] == "AuditRole"
    assert kwargs["region"] == "us-east-1"

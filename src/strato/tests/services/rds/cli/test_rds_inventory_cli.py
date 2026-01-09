from unittest import mock

from typer.testing import CliRunner

import strato.services.rds.cli.inventory as inventory_module
from strato.services.rds.cli.inventory import app
from strato.services.rds.domains.inventory.checks import RDSInventoryScanType

runner = CliRunner(mix_stderr=False)


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = runner.invoke(app, ["scan", "--json", "--region", "us-east-1"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args

    assert kwargs["check_type"] == RDSInventoryScanType.INVENTORY
    assert kwargs["json_output"] is True
    assert kwargs["region"] == "us-east-1"


@mock.patch.object(inventory_module, "run_scan")
def test_inventory_scan_requires_format(mock_run_scan):
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "Inventory data is too wide" in (result.stderr + result.stdout)

    mock_run_scan.assert_not_called()

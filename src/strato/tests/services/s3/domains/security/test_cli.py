from unittest.mock import patch

from typer.testing import CliRunner

from strato.services.s3.cli.security import app

runner = CliRunner()


def test_cli_all_command_structure():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(app, ["all", "--verbose", "--fail-on-risk"])

        assert result.exit_code == 0
        assert mock_run.called

        args = mock_run.call_args[0]
        assert args[3] is True
        assert args[4] is True


def test_cli_naming_alias_exists():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(app, ["naming"])

        assert result.exit_code == 0
        assert mock_run.called


def test_cli_encryption_defaults():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(app, ["encryption"])

        assert result.exit_code == 0

        scan_type = mock_run.call_args[0][2]
        assert scan_type == "encryption"

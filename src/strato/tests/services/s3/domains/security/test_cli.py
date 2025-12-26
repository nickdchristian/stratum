from unittest.mock import patch

from typer.testing import CliRunner

from strato.services.s3.cli.security import app
from strato.services.s3.domains.security.views import S3SecurityView

runner = CliRunner()


def test_cli_all_command_structure():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(
            app, ["all", "--verbose", "--fail-on-risk", "--org-role", "MyRole"]
        )

        assert result.exit_code == 0
        assert mock_run.called

        # In security.py, arguments are passed POSITIONALLY to run_scan.
        args = mock_run.call_args[0]
        kwargs = mock_run.call_args[1]

        # args mapping based on run_scan signature:
        # 0: scanner_cls
        # 1: result_cls
        # 2: check_type
        # 3: verbose
        # 4: fail_on_finding (from --fail-on-risk)
        # 5: json
        # 6: csv
        # 7: failures_only
        # 8: org_role

        assert args[3] is True  # verbose
        assert args[4] is True  # fail_on_risk
        assert args[8] == "MyRole"  # org_role

        # view_class is passed as a Keyword Argument
        assert kwargs.get("view_class") == S3SecurityView


def test_cli_encryption_defaults():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(app, ["encryption"])

        assert result.exit_code == 0

        args = mock_run.call_args[0]
        kwargs = mock_run.call_args[1]

        # check_type is index 2
        assert args[2] == "encryption"

        # org_role is index 8 (defaults to None)
        assert args[8] is None

        # view_class must still be present
        assert kwargs.get("view_class") == S3SecurityView
import pytest
from unittest.mock import patch
from strato.core.presenter import AuditPresenter
from strato.core.models import AuditResult


@pytest.fixture
def sample_results():
    return [
        AuditResult("arn1", "res1", "us-east-1", risk_score=0),
        AuditResult("arn2", "res2", "us-east-1", risk_score=100),
    ]


def test_print_json(sample_results):
    with patch("strato.core.presenter.console") as mock_console:
        presenter = AuditPresenter(sample_results, AuditResult)
        presenter.print_json()

        # Verify it called print_json with a list of dicts
        assert mock_console.print_json.called
        data = mock_console.print_json.call_args[1]["data"]
        assert len(data) == 2
        assert data[1]["resource_name"] == "res2"


def test_print_csv(sample_results, capsys):
    presenter = AuditPresenter(sample_results, AuditResult)
    presenter.print_csv()

    captured = capsys.readouterr()
    output = captured.out

    assert "Resource,Region,Risk Level,Reasons" in output
    assert "res1,us-east-1,SAFE" in output
    assert "res2,us-east-1,CRITICAL" in output

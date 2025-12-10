from unittest.mock import patch

import pytest

from strato.core.models import AuditResult
from strato.core.presenter import AuditPresenter


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


def test_summary_counts_total_risks():
    result_1 = AuditResult("arn:1", "resource-1", "us-east-1")
    result_1.risk_reasons = ["Risk Type A", "Risk Type B"]

    result_2 = AuditResult("arn:2", "resource-2", "us-east-1")
    result_2.risk_reasons = ["Risk Type C"]

    results = [result_1, result_2]

    with patch("strato.core.presenter.console") as mock_console:
        presenter = AuditPresenter(results, AuditResult)

        presenter._print_summary()

        expected_msg = "Found 3 risks"

        printed_text = " ".join(
            call.args[0] for call in mock_console.print.call_args_list
        )

        assert expected_msg in printed_text, (
            f"Summary logic failed! "
            f"Expected '{expected_msg}' but got: '{printed_text}'."
        )

from unittest.mock import patch
import pytest
from strato.core.models import AuditResult
from strato.core.presenter import AuditPresenter


@pytest.fixture
def sample_results():
    return [
        AuditResult("arn1", "res1", "us-east-1", account_id="111", status_score=0),
        AuditResult("arn2", "res2", "us-east-1", account_id="222", status_score=100),
    ]


def test_print_json(sample_results):
    with patch("strato.core.presenter.console") as mock_console:
        presenter = AuditPresenter(sample_results, AuditResult)
        presenter.print_json()

        assert mock_console.print_json.called
        data = mock_console.print_json.call_args[1]["data"]
        assert len(data) == 2
        assert data[0]["account_id"] == "111"


def test_print_csv(sample_results, capsys):
    presenter = AuditPresenter(sample_results, AuditResult)
    presenter.print_csv()

    captured = capsys.readouterr()
    output = captured.out

    # FIX: Expect "Account" (the generic default), not "Account ID"
    assert "Account,Resource,Region,Status,Findings" in output
    assert "111,res1,us-east-1,PASS" in output


def test_summary_counts_total_observations():
    result_1 = AuditResult("arn:1", "resource-1", "us-east-1", status_score=100)
    result_1.findings = ["Finding Type A", "Finding Type B"]
    result_2 = AuditResult("arn:2", "resource-2", "us-east-1", status_score=100)
    result_2.findings = ["Finding Type C"]
    results = [result_1, result_2]

    with patch("strato.core.presenter.console") as mock_console:
        presenter = AuditPresenter(results, AuditResult)
        presenter._print_summary()

        expected_msg = "Found 3 violations"
        printed_text = " ".join(call.args[0] for call in mock_console.print.call_args_list)
        assert expected_msg in printed_text


def test_presenter_uses_injected_view(sample_results):
    mock_view = pytest.importorskip("unittest.mock").MagicMock()
    mock_view.get_headers.return_value = ["CustomHeader"]
    mock_view.format_row.return_value = ["CustomValue"]

    with patch("strato.core.presenter.console") as mock_console:
        presenter = AuditPresenter(sample_results, AuditResult, view_class=mock_view)
        presenter.print_table("Test Table")
        mock_view.get_headers.assert_called()
        mock_view.format_row.assert_called()

import re
from io import StringIO

from rich.console import Console

from strato.core.models import AuditResult, BaseScanner
from strato.core.presenter import AuditPresenter


class MockScanner(BaseScanner):
    @property
    def service_name(self) -> str:
        return "TestService"

    def fetch_resources(self):
        return ["res1", "res2", "res3"]

    def analyze_resource(self, resource):
        return AuditResult(
            resource_arn=f"arn:{resource}",
            resource_name=resource,
            region="us-east-1",
            status_score=100 if resource == "res2" else 0,
            findings=["Bad thing"] if resource == "res2" else [],
        )


def test_base_scanner_threading():
    scanner = MockScanner()
    results = scanner.scan(silent=True)

    assert len(results) == 3
    assert isinstance(results[0], AuditResult)
    failures = [r for r in results if r.is_violation]
    assert len(failures) == 1
    assert failures[0].resource_name == "res2"
    assert failures[0].status == "CRITICAL"


def test_presenter_json(mocker, capsys):
    results = [
        AuditResult("arn:1", "bucket1", "us-east-1", status_score=0),
        AuditResult(
            "arn:2", "bucket2", "us-east-1", status_score=50, findings=["Risk"]
        ),
    ]

    # Use standard console but capture it; force_terminal=False helps reduce codes
    mock_console = Console(
        file=StringIO(), force_terminal=False, width=1000, no_color=True
    )
    mocker.patch("strato.core.presenter.console_out", mock_console)

    presenter = AuditPresenter(results)
    presenter.print_json()

    output = mock_console.file.getvalue()

    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean_output = ansi_escape.sub("", output)

    assert '"resource_name": "bucket1"' in clean_output
    assert '"status_score": 50' in clean_output


def test_presenter_csv(capsys):
    results = [AuditResult("arn:1", "bucket1", "us-east-1", status_score=0)]
    presenter = AuditPresenter(results)
    presenter.print_csv()

    captured = capsys.readouterr()
    assert "Account ID,Resource,Region,Status,Findings" in captured.out
    assert "Unknown,bucket1,us-east-1,PASS," in captured.out

from io import StringIO

import boto3
from rich.console import Console

from strato.core.models import AuditResult, BaseScanner
from strato.core.runner import _execute_multi_account_scan, run_scan


class FakeScanner(BaseScanner):
    @property
    def service_name(self):
        return "FakeService"

    def fetch_resources(self):
        return ["item"]

    def analyze_resource(self, res):
        return AuditResult("arn", "item", "us-east-1", self.account_id)


def test_run_scan_single_account(mocker, capsys):
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_boto = mocker.patch("boto3.client")
    mock_boto.return_value = mock_sts

    mock_console = Console(
        file=StringIO(), force_terminal=True, width=1000, no_color=True
    )
    mocker.patch("strato.core.presenter.console_out", mock_console)

    exit_code = run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=False,
        csv_output=False,
        failures_only=False,
    )

    assert exit_code == 0
    output = mock_console.file.getvalue()
    assert "FakeService" in output


def test_multi_account_scan_logic(org_mock, sts_mock, mocker):
    org_mock.create_organization(FeatureSet="ALL")
    org_mock.create_account(Email="a@a.com", AccountName="Account A")
    org_mock.create_account(Email="b@b.com", AccountName="Account B")

    mocker.patch("strato.core.runner.assume_role_session", return_value=boto3.Session())

    results = _execute_multi_account_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        org_role="OrganizationAccountAccessRole",
    )

    assert len(results) >= 2

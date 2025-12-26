from unittest.mock import MagicMock, patch

import pytest

from strato.core.models import AuditResult
from strato.core.runner import (
    assume_role_session,
    get_org_accounts,
    run_scan,
    scan_single_account,
)
from strato.core.scanner import BaseScanner


class MockScanner(BaseScanner):
    def __init__(self, check_type="ALL", session=None, account_id="Unknown"):
        super().__init__(check_type, session, account_id)

    @property
    def service_name(self):
        return "MockService"

    def fetch_resources(self):
        return []

    def analyze_resource(self, resource):
        return AuditResult("arn", "res", "us-east-1", account_id=self.account_id)

    def scan(self, silent=False):
        return [AuditResult("arn", "res", "us-east-1", account_id=self.account_id)]


@pytest.fixture
def mock_boto_client():
    with patch("boto3.client") as mock:
        yield mock


@pytest.fixture
def mock_boto_session():
    with patch("boto3.Session") as mock:
        yield mock


def test_get_org_accounts(mock_boto_client):
    mock_org = MagicMock()
    mock_boto_client.return_value = mock_org

    paginator = MagicMock()
    mock_org.get_paginator.return_value = paginator

    # Mock Response: 2 Active accounts, 1 Suspended
    paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111", "Name": "Account A", "Status": "ACTIVE"},
                {"Id": "222", "Name": "Account B", "Status": "SUSPENDED"},
            ]
        },
        {
            "Accounts": [
                {"Id": "333", "Name": "Account C", "Status": "ACTIVE"},
            ]
        },
    ]

    accounts = get_org_accounts()

    assert len(accounts) == 2
    assert accounts[0]["Id"] == "111"
    assert accounts[1]["Id"] == "333"
    assert "222" not in [a["Id"] for a in accounts]


def test_assume_role_session(mock_boto_client, mock_boto_session):
    mock_sts = MagicMock()
    mock_boto_client.return_value = mock_sts

    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA...",
            "SecretAccessKey": "SECRET...",
            "SessionToken": "TOKEN...",
        }
    }

    session = assume_role_session("123456789012", "MyRole")

    mock_sts.assume_role.assert_called_with(
        RoleArn="arn:aws:iam::123456789012:role/MyRole",
        RoleSessionName="StratoAuditSession",
    )

    mock_boto_session.assert_called_with(
        aws_access_key_id="AKIA...",
        aws_secret_access_key="SECRET...",
        aws_session_token="TOKEN...",
    )
    assert session is not None


def test_scan_single_account_success(mock_boto_client):
    # Mock assume_role to succeed
    with patch("strato.core.runner.assume_role_session") as mock_assume:
        mock_assume.return_value = MagicMock()

        account = {"Id": "111", "Name": "TestAccount"}
        results, error = scan_single_account(account, "MyRole", MockScanner, "ALL")

        assert error is None
        assert len(results) == 1
        assert results[0].account_id == "111"


def test_scan_single_account_access_denied(mock_boto_client):
    # Mock assume_role to fail (return None)
    with patch("strato.core.runner.assume_role_session") as mock_assume:
        mock_assume.return_value = None

        account = {"Id": "111", "Name": "TestAccount"}
        results, error = scan_single_account(account, "MyRole", MockScanner, "ALL")

        assert results == []
        assert "Access Denied" in error


def test_run_scan_multi_account_integration():
    """
    Tests the full flow of run_scan when --org-role is provided.
    """
    with (
        patch("strato.core.runner.get_org_accounts") as mock_get_accounts,
        patch("strato.core.runner.scan_single_account") as mock_scan_single,
        patch("strato.core.runner.AuditPresenter") as mock_presenter_cls,
    ):
        # Setup Mocks
        mock_get_accounts.return_value = [
            {"Id": "111", "Name": "Acc1"},
            {"Id": "222", "Name": "Acc2"},
        ]

        # Acc1 succeeds, Acc2 fails
        mock_scan_single.side_effect = [
            ([AuditResult("arn1", "res1", "us-east-1", account_id="111")], None),
            ([], "Access Denied"),
        ]

        # Run Scan
        run_scan(
            scanner_cls=MockScanner,
            result_cls=AuditResult,
            check_type="ALL",
            verbose=False,
            fail_on_finding=False,
            json_output=False,
            csv_output=False,
            failures_only=False,
            org_role="OrgRole",
            view_class="MockView"
        )

        # Verify scan_single_account was called for each account
        assert mock_scan_single.call_count == 2

        # Verify Presenter received aggregated results
        # call_args[0][0] is the results list passed to __init__
        results_passed = mock_presenter_cls.call_args[0][0]
        assert len(results_passed) == 1
        assert results_passed[0].account_id == "111"

        # Verify view_class made it to the Presenter (it's passed as a kwarg in run_scan)
        presenter_kwargs = mock_presenter_cls.call_args[1]
        assert presenter_kwargs.get("view_class") == "MockView"
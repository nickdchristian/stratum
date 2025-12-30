from datetime import datetime

import pytest

from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanType,
)
from strato.services.s3.domains.security.views import S3SecurityView


@pytest.fixture
def sample_result():
    return S3SecurityResult(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_name="test-bucket",
        region="us-east-1",
        account_id="123456789012",
        creation_date=datetime(2025, 1, 1, 12, 0, 0),
        public_access_block_status=True,
        ssl_enforced=True,
        encryption="aws:kms",
        sse_c=True,
        versioning="Enabled",
        check_type=S3SecurityScanType.ALL,
        name_predictability="LOW",
    )


def test_get_headers_all():
    headers = S3SecurityView.get_headers(S3SecurityScanType.ALL)
    assert "Bucket Name" in headers
    assert "Status" in headers
    assert "Encryption" not in headers


def test_get_headers_specific_scan():
    headers = S3SecurityView.get_headers(S3SecurityScanType.ENCRYPTION)
    assert "Encryption" in headers
    assert "SSE-C" in headers
    assert "Status" in headers


def test_format_row_all_pass(sample_result):
    row = S3SecurityView.format_row(sample_result)

    assert "test-bucket" in row
    assert "2025-01-01" in row

    status_idx = -2
    assert "[green]PASS[/green]" in row[status_idx]


def test_format_row_dynamic_columns():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="b",
        region="us",
        account_id="1",
        encryption="AES256",
        sse_c=True,
        check_type=S3SecurityScanType.ENCRYPTION,
    )

    row = S3SecurityView.format_row(result)

    assert len(row) == 8
    assert "[green]AES256[/green]" in row[4]
    assert "[green]Blocked[/green]" in row[5]


def test_format_csv_row(sample_result):
    row = S3SecurityView.format_csv_row(sample_result)

    assert "test-bucket" in row
    assert "aws:kms" in row
    assert "Enabled" in row
    assert "PASS" in row


def test_render_bool_helper():
    assert "green" in S3SecurityView._render_bool(True)
    assert "red" in S3SecurityView._render_bool(False)

    assert "red" in S3SecurityView._render_bool(True, invert=True)
    assert "green" in S3SecurityView._render_bool(False, invert=True)


def test_render_policy_helper():
    assert "green" in S3SecurityView._render_policy("Private")
    assert "yellow" in S3SecurityView._render_policy("Potentially Public")
    assert "red" in S3SecurityView._render_policy("Public")


def test_render_acl_helper():
    assert "green" in S3SecurityView._render_acl("Disabled", False)
    assert "yellow" in S3SecurityView._render_acl("Enabled", True)
    assert "red" in S3SecurityView._render_acl("Enabled", False)


def test_render_predictability_helper():
    assert "green" in S3SecurityView._render_predictability("LOW")
    assert "yellow" in S3SecurityView._render_predictability("HIGH")

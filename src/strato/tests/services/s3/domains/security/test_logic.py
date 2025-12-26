from datetime import datetime

import pytest

from strato.core.scoring import ObservationLevel
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanType,
)
from strato.services.s3.domains.security.views import S3SecurityView  # NEW IMPORT


@pytest.fixture
def safe_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::safe-bucket-3a9f1c4d",
        resource_name="safe-bucket-3a9f1c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_block_status=True,
        policy_access="Private",
        ssl_enforced=True,
        encryption="AES256",
        sse_c=True,
        acl_status="Disabled",
        versioning="Enabled",
        mfa_delete="Enabled",
        object_lock="Enabled",
        check_type=S3SecurityScanType.ALL,
        log_sources=[],
    )


@pytest.fixture
def observation_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::risky-bucket-7b8e9f0a",
        resource_name="risky-bucket-7b8e9f0a",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_block_status=False,
        encryption="None",
        acl_status="Enabled",
        versioning="Suspended",
        mfa_delete="Disabled",
        object_lock="Disabled",
        check_type=S3SecurityScanType.ALL,
        log_sources=[],
    )


@pytest.fixture
def policy_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::policy-bucket-1a2b3c4d",
        resource_name="policy-bucket-1a2b3c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        policy_access="Private",
        ssl_enforced=True,
        check_type=S3SecurityScanType.POLICY,
    )


def test_observation_level_all_safe(safe_result):
    assert safe_result.status_score == ObservationLevel.PASS
    assert safe_result.status == "PASS"
    assert len(safe_result.findings) == 0


def test_observation_level_critical(safe_result):
    safe_result.public_access_block_status = False
    safe_result._evaluate_status()

    assert safe_result.status_score >= ObservationLevel.CRITICAL
    assert "Public Access Allowed" in safe_result.findings


def test_observation_level_medium(safe_result):
    safe_result.encryption = "None"
    safe_result.sse_c = True
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.MEDIUM
    assert "Encryption Missing" in safe_result.findings


def test_observation_level_ssec_warning(safe_result):
    safe_result.sse_c = False
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.LOW
    assert "SSE-C Not Blocked" in safe_result.findings


def test_ignore_mfa_lock_on_standard_buckets(observation_result):
    observation_result.public_access_block_status = True
    observation_result.encryption = "AES256"
    observation_result.sse_c = True
    observation_result.acl_status = "Disabled"
    observation_result.ssl_enforced = True
    observation_result.policy_access = "Private"
    observation_result.versioning = "Enabled"
    observation_result.mfa_delete = "Disabled"
    observation_result.object_lock = "Disabled"
    observation_result.log_sources = []

    observation_result._evaluate_status()

    assert observation_result.status_score == ObservationLevel.PASS
    assert "MFA Delete Disabled" not in str(observation_result.findings)


def test_status_scoring_mfa_object_lock_flagged_for_log_buckets(observation_result):
    observation_result.public_access_block_status = True
    observation_result.encryption = "AES256"
    observation_result.sse_c = True
    observation_result.acl_status = "Disabled"
    observation_result.ssl_enforced = True
    observation_result.policy_access = "Private"
    observation_result.versioning = "Enabled"
    observation_result.log_sources = ["cloudtrail.amazonaws.com"]
    observation_result._evaluate_status()

    assert observation_result.status_score >= ObservationLevel.LOW
    reasons = " ".join(observation_result.findings)
    assert "MFA Delete Disabled" in reasons
    assert "Object Lock Disabled" in reasons


def test_status_scoring_filtering(safe_result):
    """
    Ensures that if we run a specific check (ENCRYPTION), we don't fail
    on unrelated issues (Public Access).
    """
    safe_result.public_access_block_status = False
    safe_result.check_type = S3SecurityScanType.ENCRYPTION
    safe_result.encryption = "AES256"
    safe_result.sse_c = True
    safe_result._evaluate_status()

    assert safe_result.status_score == ObservationLevel.PASS



def test_render_style_integration(safe_result):
    safe_result.check_type = S3SecurityScanType.ENCRYPTION

    row = S3SecurityView.format_row(safe_result)

    # Row: [Account, Resource, Region, Date, Encryption, SSE-C, Status, Findings]
    enc_render = row[4]

    assert "[green]AES256[/green]" in enc_render


def test_render_style_risky(observation_result):
    observation_result.check_type = S3SecurityScanType.PUBLIC_ACCESS

    row = S3SecurityView.format_row(observation_result)

    # Row: [Account, Resource, Region, Date, BlockStatus, Status, Findings]
    pub_render = row[4]

    assert "[red]OPEN[/red]" in pub_render


def test_all_scan_table_is_summary(safe_result):
    """
    Verifies that the "ALL" scan table suppresses detailed columns.
    """
    safe_result.check_type = S3SecurityScanType.ALL

    headers = S3SecurityView.get_headers(S3SecurityScanType.ALL)
    row = S3SecurityView.format_row(safe_result)

    assert len(headers) == 6
    assert len(row) == 6
    assert "Account ID" in headers
    assert "Encryption" not in headers
    assert "Object Lock" not in headers


def test_all_scan_csv_is_full_detail(safe_result):
    """
    Verifies that the "ALL" scan CSV *includes* detailed columns.
    """
    safe_result.check_type = S3SecurityScanType.ALL

    headers = S3SecurityView.get_csv_headers(S3SecurityScanType.ALL)
    row = S3SecurityView.format_csv_row(safe_result)

    assert len(headers) > 6
    assert len(row) > 6
    assert len(headers) == len(row)
    assert "Account ID" in headers
    assert "Encryption" in headers
    assert "SSE-C" in headers
    assert "Object Lock" in headers
    assert "MFA Delete" in headers


def test_specific_scan_headers_match(safe_result):
    check_type = S3SecurityScanType.OBJECT_LOCK
    safe_result.check_type = check_type

    table_headers = S3SecurityView.get_headers(check_type)
    csv_headers = S3SecurityView.get_csv_headers(check_type)

    assert table_headers == csv_headers
    assert "Object Lock" in table_headers
    assert len(table_headers) == 7


def test_csv_row_alignment(safe_result):
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type
        headers = S3SecurityView.get_csv_headers(scan_type)
        row = S3SecurityView.format_csv_row(safe_result)
        assert len(headers) == len(row)


def test_table_row_alignment(safe_result):
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type
        headers = S3SecurityView.get_headers(scan_type)
        row = S3SecurityView.format_row(safe_result)
        assert len(headers) == len(row)


def test_policy_render_style_safe(policy_result):
    row = S3SecurityView.format_row(policy_result)
    # Row: [Account, Resource, Region, Date, Access, SSL, Status, Findings]
    access_render = row[4]
    ssl_render = row[5]

    assert "Private" in access_render
    assert "green" in access_render
    assert "Yes" in ssl_render
    assert "green" in ssl_render


def test_policy_render_style_risky(policy_result):
    policy_result.policy_access = "Public"
    policy_result.ssl_enforced = False
    row = S3SecurityView.format_row(policy_result)

    assert "Public" in row[4]
    assert "red" in row[4]
    assert "No" in row[5]
    assert "red" in row[5]


def test_policy_render_style_warning(policy_result):
    policy_result.policy_access = "Potentially Public"
    row = S3SecurityView.format_row(policy_result)

    assert "Potentially Public" in row[4]
    assert "yellow" in row[4]


def test_policy_scan_csv_headers(policy_result):
    headers = S3SecurityView.get_csv_headers(S3SecurityScanType.POLICY)

    assert "Account ID" in headers
    assert "Policy Access" in headers
    assert "SSL Enforced" in headers
    assert "Encryption" not in headers


@pytest.fixture
def website_result():
    return S3SecurityResult(
        account_id="111122223333",
        resource_arn="arn:aws:s3:::website-bucket-123",
        resource_name="website-bucket-123",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        website_hosting=False,
        check_type=S3SecurityScanType.WEBSITE_HOSTING,
    )


def test_website_render_style_safe(website_result):
    website_result.website_hosting = False
    row = S3SecurityView.format_row(website_result)
    render = row[4]

    assert "Disabled" in str(render)
    assert "green" in str(render)

def test_website_render_style_risky(website_result):
    website_result.website_hosting = True
    row = S3SecurityView.format_row(website_result)
    render = row[4]

    assert "Enabled" in str(render)
    assert "red" in str(render)


def test_website_csv_headers(website_result):
    headers = S3SecurityView.get_csv_headers(S3SecurityScanType.WEBSITE_HOSTING)

    assert "Account ID" in headers
    assert "Website Hosting" in headers
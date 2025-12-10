from datetime import datetime

import pytest

from strato.core.scoring import RiskWeight
from strato.services.s3.domains.security import S3SecurityResult, S3SecurityScanType


@pytest.fixture
def safe_result():
    """Returns a completely safe S3SecurityResult."""
    return S3SecurityResult(
        resource_arn="arn:aws:s3:::safe-bucket-3a9f1c4d",
        resource_name="safe-bucket-3a9f1c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_blocked=True,
        policy_access="Private",
        ssl_enforced=True,
        encryption="AES256",
        sse_c_blocked=True,
        acl_status="Disabled",
        versioning="Enabled",
        mfa_delete="Enabled",
        object_lock="Enabled",
        check_type=S3SecurityScanType.ALL,
    )


@pytest.fixture
def risky_result():
    """Returns a result with multiple risks."""
    return S3SecurityResult(
        resource_arn="arn:aws:s3:::risky-bucket-7b8e9f0a",
        resource_name="risky-bucket-7b8e9f0a",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_blocked=False,
        encryption="None",
        acl_status="Enabled",
        versioning="Suspended",
        mfa_delete="Disabled",
        object_lock="Disabled",
        check_type=S3SecurityScanType.ALL,
    )


@pytest.fixture
def policy_result():
    """Returns a result initialized for Policy scanning."""
    return S3SecurityResult(
        resource_arn="arn:aws:s3:::policy-bucket-1a2b3c4d",
        resource_name="policy-bucket-1a2b3c4d",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        # Default safe state for policy
        policy_access="Private",
        ssl_enforced=True,
        check_type=S3SecurityScanType.POLICY,
    )


def test_risk_scoring_all_safe(safe_result):
    """Verify a safe bucket has 0 risk score."""
    assert safe_result.risk_score == RiskWeight.NONE
    assert safe_result.risk_level == "SAFE"
    assert len(safe_result.risk_reasons) == 0


def test_risk_scoring_critical(safe_result):
    """Verify Public Access triggers CRITICAL risk."""
    safe_result.public_access_blocked = False
    safe_result._evaluate_risk()

    assert safe_result.risk_score >= RiskWeight.CRITICAL
    assert "Public Access Allowed" in safe_result.risk_reasons


def test_risk_scoring_medium(safe_result):
    """Verify Encryption Missing triggers MEDIUM risk."""
    safe_result.encryption = "None"
    safe_result.sse_c_blocked = True
    safe_result._evaluate_risk()

    assert safe_result.risk_score == RiskWeight.MEDIUM
    assert "Encryption Missing" in safe_result.risk_reasons


def test_risk_scoring_ssec_warning(safe_result):
    """Verify SSE-C Allowed triggers LOW risk."""
    safe_result.sse_c_blocked = False
    safe_result._evaluate_risk()

    assert safe_result.risk_score == RiskWeight.LOW
    assert "SSE-C Not Blocked" in safe_result.risk_reasons


def test_risk_scoring_filtering(safe_result):
    """Verify risks are ignored if they are not part of the active check_type."""
    # Set a critical risk (Public Access)
    safe_result.public_access_blocked = False

    # But run a scan ONLY for Encryption
    safe_result.check_type = S3SecurityScanType.ENCRYPTION

    safe_result.encryption = "AES256"
    safe_result.sse_c_blocked = True

    safe_result._evaluate_risk()

    # Should be safe because we aren't checking public access
    assert safe_result.risk_score == RiskWeight.NONE


def test_render_style_integration(safe_result):
    """
    Verify that security.py correctly uses style.py for rendering.
    We check for the presence of Rich color tags.
    """
    safe_result.check_type = S3SecurityScanType.ENCRYPTION
    row = safe_result.get_table_row()

    # Structure: [Name, Region, Date, Encryption, Risk, Reasons]
    enc_render = row[3]

    # Should be green because it's AES256
    assert "[green]AES256[/green]" in enc_render


def test_render_style_risky(risky_result):
    """Verify risky values are rendered with warning colors."""
    risky_result.check_type = S3SecurityScanType.PUBLIC_ACCESS
    row = risky_result.get_table_row()

    # Structure: [Name, Region, Date, Public, Risk, Reasons]
    pub_render = row[3]

    # Should be red because it is NOT blocked
    assert "[red]OPEN[/red]" in pub_render


def test_all_scan_table_is_summary(safe_result):
    """
    Regression Test: Ensure 'ALL' scan tables are readable summaries.
    They should NOT contain the 5+ dynamic columns.
    """
    safe_result.check_type = S3SecurityScanType.ALL
    headers = safe_result.get_headers(S3SecurityScanType.ALL)
    row = safe_result.get_table_row()

    # Expectation: Name, Region, Date, Risk, Reasons (5 columns)
    assert len(headers) == 5
    assert len(row) == 5

    assert "Encryption" not in headers
    assert "Object Lock" not in headers


def test_all_scan_csv_is_full_detail(safe_result):
    """
    Regression Test: Ensure 'ALL' scan CSVs contain ALL data.
    They MUST include the dynamic columns hidden from the table.
    """
    safe_result.check_type = S3SecurityScanType.ALL
    headers = safe_result.get_csv_headers(S3SecurityScanType.ALL)
    row = safe_result.get_csv_row()

    assert len(headers) > 5
    assert len(row) > 5
    assert len(headers) == len(row)

    assert "Encryption" in headers
    assert "SSE-C Blocked" in headers
    assert "Object Lock" in headers
    assert "MFA Delete" in headers


def test_specific_scan_headers_match(safe_result):
    """
    For specific scans (e.g. OBJECT_LOCK), Table and CSV should be identical.
    """
    check_type = S3SecurityScanType.OBJECT_LOCK
    safe_result.check_type = check_type

    table_headers = safe_result.get_headers(check_type)
    csv_headers = safe_result.get_csv_headers(check_type)

    # Both should show the specific column
    assert table_headers == csv_headers
    assert "Object Lock" in table_headers
    assert len(table_headers) == 6  # Name, Region, Date, Lock, Risk, Reasons


def test_csv_row_alignment(safe_result):
    """Ensure CSV Row matches CSV Headers for every scan type."""
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type

        headers = safe_result.get_csv_headers(scan_type)
        row = safe_result.get_csv_row()

        assert len(headers) == len(row), f"CSV Alignment failed for {scan_type}"


def test_table_row_alignment(safe_result):
    """Ensure Table Row matches Table Headers for every scan type."""
    for scan_type in S3SecurityScanType:
        safe_result.check_type = scan_type

        headers = safe_result.get_headers(scan_type)
        row = safe_result.get_table_row()

        assert len(headers) == len(row), f"Table Alignment failed for {scan_type}"


def test_json_filtering(safe_result):
    """Verify to_dict filters out irrelevant fields based on scan type."""
    safe_result.check_type = S3SecurityScanType.OBJECT_LOCK

    data = safe_result.to_dict()

    # Core fields
    assert "resource_name" in data
    assert "risk_score" in data

    # Relevant field
    assert "object_lock" in data

    # Irrelevant fields (should be absent)
    assert "encryption" not in data
    assert "public_access_blocked" not in data
    assert "versioning" not in data


def test_policy_scoring_safe(policy_result):
    """Verify a Private, SSL-Enforced bucket has 0 risk."""
    assert policy_result.risk_score == RiskWeight.NONE
    assert policy_result.risk_level == "SAFE"
    assert len(policy_result.risk_reasons) == 0


def test_policy_scoring_critical_public(policy_result):
    """Verify 'Public' policy access triggers CRITICAL risk."""
    policy_result.policy_access = "Public"
    policy_result._evaluate_risk()

    assert policy_result.risk_score >= RiskWeight.CRITICAL
    assert "Bucket Policy Allows Public Access" in policy_result.risk_reasons


def test_policy_scoring_high_potentially_public(policy_result):
    """Verify 'Potentially Public' triggers HIGH risk."""
    policy_result.policy_access = "Potentially Public"
    policy_result._evaluate_risk()

    assert policy_result.risk_score == RiskWeight.HIGH
    assert (
        "Bucket Policy Potentially Allows Public Access" in policy_result.risk_reasons
    )


def test_policy_scoring_medium_no_ssl(policy_result):
    """Verify missing SSL enforcement triggers MEDIUM risk."""
    policy_result.ssl_enforced = False
    policy_result._evaluate_risk()

    assert policy_result.risk_score == RiskWeight.MEDIUM
    assert "SSL Not Enforced" in policy_result.risk_reasons


def test_policy_scoring_cumulative(policy_result):
    """Verify risks stack (e.g., Potentially Public + No SSL)."""
    policy_result.policy_access = "Potentially Public"
    policy_result.ssl_enforced = False
    policy_result._evaluate_risk()

    # High (Potential Public) + Medium (No SSL)
    expected_score = RiskWeight.HIGH + RiskWeight.MEDIUM
    assert policy_result.risk_score == expected_score
    assert len(policy_result.risk_reasons) == 2


def test_policy_render_style_safe(policy_result):
    """Verify safe values render with green PASS color."""
    row = policy_result.get_table_row()

    # Structure: [Name, Region, Date, Policy Access, SSL Enforced, Risk, Reasons]
    access_render = row[3]
    ssl_render = row[4]

    assert "Private" in access_render
    assert "green" in access_render  # AuditStatus.PASS

    assert "True" in ssl_render
    assert "green" in ssl_render  # AuditStatus.PASS


def test_policy_render_style_risky(policy_result):
    """Verify risky values render with FAIL/WARN colors."""
    policy_result.policy_access = "Public"
    policy_result.ssl_enforced = False

    row = policy_result.get_table_row()

    # Public -> Red (FAIL)
    assert "Public" in row[3]
    assert "red" in row[3]

    # SSL False -> Red (FAIL)
    assert "False" in row[4]
    assert "red" in row[4]


def test_policy_render_style_warning(policy_result):
    """Verify 'Potentially Public' renders as a Warning."""
    policy_result.policy_access = "Potentially Public"

    row = policy_result.get_table_row()

    # Potentially Public -> Yellow (WARN)
    assert "Potentially Public" in row[3]
    assert "yellow" in row[3]


def test_policy_scan_csv_headers(policy_result):
    """Verify CSV headers include the specific Policy columns."""
    headers = policy_result.get_csv_headers(S3SecurityScanType.POLICY)

    assert "Policy Access" in headers
    assert "SSL Enforced" in headers

    # Should NOT include unrelated columns from other scans
    assert "Encryption" not in headers
    assert "MFA Delete" not in headers


def test_policy_json_structure(policy_result):
    """Verify to_dict includes policy fields."""
    policy_result.policy_access = "Public"
    policy_result.ssl_enforced = False

    data = policy_result.to_dict()

    assert data["policy_access"] == "Public"
    assert data["ssl_enforced"] is False

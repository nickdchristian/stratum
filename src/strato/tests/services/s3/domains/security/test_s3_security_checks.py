import uuid
from datetime import datetime

from strato.core.models import ObservationLevel
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanner,
    S3SecurityScanType,
)


def test_result_evaluation_all_clear():
    result = S3SecurityResult(
        resource_arn="arn:aws:s3:::safe-bucket",
        resource_name="safe-bucket",
        region="us-east-1",
        account_id="123",
        public_access_block_status=True,
        ssl_enforced=True,
        policy_access="Private",
        encryption="AES256",
        versioning="Enabled",
        acl_status="Disabled",
        sse_c=True,
        name_predictability="LOW",
        check_type=S3SecurityScanType.ALL,
    )
    assert result.status_score == 0
    assert result.status == "PASS"
    assert not result.findings


def test_result_evaluation_public_access():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        public_access_block_status=False,
        check_type=S3SecurityScanType.PUBLIC_ACCESS,
    )
    assert result.status_score >= ObservationLevel.CRITICAL
    assert "Public Access Allowed" in result.findings


def test_result_evaluation_policy_issues():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        ssl_enforced=False,
        policy_access="Potentially Public",
        check_type=S3SecurityScanType.POLICY,
    )
    assert result.status_score >= ObservationLevel.HIGH
    assert "SSL Not Enforced" in result.findings
    assert "Bucket Policy Potentially Allows Public Access" in result.findings


def test_result_evaluation_encryption():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        encryption="None",
        sse_c=False,
        check_type=S3SecurityScanType.ENCRYPTION,
    )
    assert result.status_score >= ObservationLevel.MEDIUM
    assert "Encryption Missing" in result.findings
    assert "SSE-C Not Blocked" in result.findings


def test_result_evaluation_acls_logging():
    res_log = S3SecurityResult(
        resource_arn="arn",
        resource_name="b",
        region="us",
        account_id="1",
        acl_status="Enabled",
        log_target=True,
        check_type=S3SecurityScanType.ACLS,
    )
    assert res_log.status_score == ObservationLevel.MEDIUM

    res_std = S3SecurityResult(
        resource_arn="arn",
        resource_name="b",
        region="us",
        account_id="1",
        acl_status="Enabled",
        log_target=False,
        check_type=S3SecurityScanType.ACLS,
    )
    assert res_std.status_score == ObservationLevel.HIGH


def test_result_evaluation_versioning_mfa():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        versioning="Enabled",
        mfa_delete="Disabled",
        log_sources=["cloudtrail.amazonaws.com"],
        check_type=S3SecurityScanType.VERSIONING,
    )
    assert result.status_score >= ObservationLevel.LOW
    assert any("MFA Delete Disabled" in f for f in result.findings)


def test_result_evaluation_website_hosting():
    result = S3SecurityResult(
        resource_arn="arn",
        resource_name="bucket",
        region="us",
        account_id="123",
        website_hosting=True,
        check_type=S3SecurityScanType.WEBSITE_HOSTING,
    )
    assert result.status_score >= ObservationLevel.HIGH
    assert "Static Website Hosting Enabled" in result.findings


def test_entropy_calculation():
    assert S3SecurityScanner._calculate_entropy("test") == "HIGH"
    assert S3SecurityScanner._calculate_entropy("backup") == "HIGH"
    assert S3SecurityScanner._calculate_entropy("my-company-backup-2024") == "MODERATE"

    random_bucket = "bucket-" + str(uuid.uuid4())
    assert S3SecurityScanner._calculate_entropy(random_bucket) == "LOW"


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.security.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "us-west-2"
    mock_client.get_public_access_status.return_value = True
    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
        "Log_Sources": [],
    }
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "aws:kms",
        "SSECBlocked": True,
    }
    mock_client.get_acl_status.return_value = {"Status": "Disabled"}
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": True,
    }
    mock_client.get_object_lock_details.return_value = {"Status": False}
    mock_client.get_website_hosting_status.return_value = False

    scanner = S3SecurityScanner(check_type=S3SecurityScanType.ALL)

    safe_name = "bucket-" + str(uuid.uuid4())
    bucket_data = {"Name": safe_name, "CreationDate": datetime(2025, 1, 1)}
    result = scanner.analyze_resource(bucket_data)

    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == safe_name
    assert result.region == "us-west-2"
    assert result.public_access_block_status is True
    assert result.ssl_enforced is True
    assert result.encryption == "aws:kms"
    assert result.status == "PASS"


def test_scanner_partial_scan(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.security.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value
    mock_client.get_bucket_region.return_value = "us-east-1"
    mock_client.get_encryption_status.return_value = {"SSEAlgorithm": "AES256"}

    scanner = S3SecurityScanner(check_type=S3SecurityScanType.ENCRYPTION)

    result = scanner.analyze_resource({"Name": "test"})

    assert result.encryption == "AES256"
    mock_client.get_bucket_policy.assert_not_called()
    mock_client.get_versioning_status.assert_not_called()

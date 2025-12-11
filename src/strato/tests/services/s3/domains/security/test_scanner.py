from datetime import datetime
from unittest.mock import MagicMock, patch

from strato.services.s3.domains.security import (
    S3SecurityResult,
    S3SecurityScanner,
)


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_analyze_resource(mock_client_cls):
    """
    Verifies that the scanner correctly maps raw AWS data to an S3SecurityResult,
    including the account_id and risk scoring.
    """
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "eu-west-1"
    mock_client.get_public_access_status.return_value = False

    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "AES256",
        "SSECBlocked": True,
    }

    mock_client.get_acl_status.return_value = "Disabled"
    mock_client.get_object_lock_status.return_value = "Enabled"
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": "Enabled",
    }

    mock_client.get_website_hosting_status.return_value = False

    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
        "Log_Sources": [],
    }

    raw_bucket_data = {
        "Name": "risk-bucket-a1b2c3d4",
        "BucketArn": "arn:aws:s3:::risk-bucket-a1b2c3d4",
        "CreationDate": datetime(2023, 5, 5),
    }

    scanner = S3SecurityScanner(account_id="123456789012")
    result = scanner.analyze_resource(raw_bucket_data)

    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == "risk-bucket-a1b2c3d4"
    assert result.account_id == "123456789012"
    assert result.encryption == "AES256"
    assert result.sse_c is True

    assert result.risk_level == "CRITICAL"
    assert len(result.risk_reasons) == 1
    assert "Public Access Allowed" in result.risk_reasons


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_handles_access_denied(mock_client_cls):
    """
    Ensure the scanner correctly processes the 'default/safe' values
    returned by S3Client when AWS denies access.
    """
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "us-east-1"

    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "None",
        "SSECBlocked": False,
    }

    mock_client.get_public_access_status.return_value = True
    mock_client.get_acl_status.return_value = "Unknown"
    mock_client.get_object_lock_status.return_value = "Unknown"
    mock_client.get_versioning_status.return_value = {
        "Status": "Unknown",
        "MFADelete": "Unknown",
    }
    mock_client.get_website_hosting_status.return_value = False
    mock_client.get_bucket_policy.return_value = {
        "Access": "Unknown",
        "SSL_Enforced": False,
        "Log_Sources": [],
    }

    scanner = S3SecurityScanner(account_id="999888777")

    result = scanner.analyze_resource(
        {"Name": "access-denied-bucket", "CreationDate": datetime.now()}
    )

    assert result.resource_name == "access-denied-bucket"
    assert result.account_id == "999888777"

    assert result.encryption == "None"
    assert "Encryption Missing" in result.risk_reasons


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_session_injection(mock_client_cls):
    """
    Ensure the scanner accepts a boto3 session (for multi-account assumes)
    and passes it correctly to the underlying S3Client.
    """
    mock_session = MagicMock()

    scanner = S3SecurityScanner(session=mock_session, account_id="55555")

    mock_client_cls.assert_called_with(session=mock_session)
    assert scanner.account_id == "55555"


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_detects_log_bucket(mock_client_cls):
    """
    Verifies that if the client detects log sources, they are passed to the result
    and risk logic flags missing protections.
    """
    mock_client = mock_client_cls.return_value
    mock_client.get_public_access_status.return_value = True
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "AES256",
        "SSECBlocked": True,
    }
    mock_client.get_acl_status.return_value = "Disabled"

    # FIX: Status must be Enabled to fall through to MFA check
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": "Disabled",
    }

    mock_client.get_object_lock_status.return_value = "Disabled"
    mock_client.get_website_hosting_status.return_value = False

    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
        "Log_Sources": ["cloudtrail.amazonaws.com"],
    }

    scanner = S3SecurityScanner(account_id="123")
    result = scanner.analyze_resource(
        {"Name": "logs-bucket", "CreationDate": datetime.now()}
    )

    assert result.log_sources == ["cloudtrail.amazonaws.com"]
    risk_strings = " ".join(result.risk_reasons)
    assert "MFA Delete Disabled" in risk_strings
    assert "Object Lock Disabled" in risk_strings

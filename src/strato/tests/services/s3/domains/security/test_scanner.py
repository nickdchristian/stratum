from datetime import datetime
from unittest.mock import patch

from botocore.exceptions import ClientError

from strato.services.s3.domains.security import (
    S3SecurityResult,
    S3SecurityScanner,
)


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_analyze_resource(mock_client_cls):
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
    }

    raw_bucket_data = {
        "Name": "risk-bucket-a1b2c3d4",
        "BucketArn": "arn:aws:s3:::risk-bucket-a1b2c3d4",
        "CreationDate": datetime(2023, 5, 5),
    }

    scanner = S3SecurityScanner()
    result = scanner.analyze_resource(raw_bucket_data)

    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == "risk-bucket-a1b2c3d4"
    assert result.encryption == "AES256"
    assert result.sse_c_blocked is True

    assert result.risk_level == "CRITICAL"
    assert len(result.risk_reasons) == 1
    assert "Public Access Allowed" in result.risk_reasons

    @patch("strato.services.s3.domains.security.S3Client")
    def test_scanner_handles_access_denied(mock_client_cls):
        """
        Ensure the scanner swallows ClientErrors (like AccessDenied)
        and returns safe/unknown defaults rather than crashing.
        """
        mock_client = mock_client_cls.return_value

        # Simulate a partial failure: We can read the bucket region...
        mock_client.get_bucket_region.return_value = "us-east-1"

        # ...but we get ACCESS DENIED when checking encryption.
        mock_client.get_encryption_status.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
            "GetBucketEncryption",
        )

        # Mock other calls to prevent unrelated errors
        mock_client.get_public_access_status.return_value = False
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
        }

        scanner = S3SecurityScanner()

        # Execute the analysis
        result = scanner.analyze_resource(
            {"Name": "access-denied-bucket", "CreationDate": datetime.now()}
        )

        # Assertions
        # It should have finished without raising an exception
        assert result.resource_name == "access-denied-bucket"

        assert result.encryption == "None"
        assert "Encryption Missing" in result.risk_reasons

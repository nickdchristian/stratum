from datetime import datetime
from unittest.mock import patch

from strato.services.s3.domains.security import (
    S3SecurityResult,
    S3SecurityScanner,
)


@patch("strato.services.s3.domains.security.S3Client")
def test_scanner_analyze_resource(mock_client_cls):
    mock_client = mock_client_cls.return_value
    mock_client.get_bucket_region.return_value = "eu-west-1"
    mock_client.get_public_access_status.return_value = False  # Risk
    mock_client.get_encryption_status.return_value = "None"  # Risk
    mock_client.get_public_access_status.return_value = False  # Risk
    mock_client.get_encryption_status.return_value = "None"  # Risk
    mock_client.get_acl_status.return_value = "Disabled"  # Safe

    raw_bucket_data = {
        "Name": "risk-bucket",
        "BucketArn": "arn:aws:s3:::risk-bucket",
        "CreationDate": datetime(2023, 5, 5),
    }

    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": "Enabled",
    }

    scanner = S3SecurityScanner()
    result = scanner.analyze_resource(raw_bucket_data)

    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == "risk-bucket"
    assert result.region == "eu-west-1"

    assert result.risk_level == "CRITICAL"
    assert len(result.risk_reasons) == 2

import pytest
from datetime import datetime
from strato.services.s3.domains.security import (
    S3SecurityResult,
    S3SecurityScanType,
)


@pytest.fixture
def base_s3_result():
    """Returns a perfectly safe S3 result to modify in tests."""
    return S3SecurityResult(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_name="test-bucket",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_blocked=True,
        encryption="AES256",
        check_type=S3SecurityScanType.ALL,
    )

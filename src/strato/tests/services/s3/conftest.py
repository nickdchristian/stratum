from datetime import datetime

import pytest

from strato.services.s3.domains.security import S3SecurityResult, S3SecurityScanType


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
        sse_c_blocked=True,
        policy_access="Private",
        ssl_enforced=True,
        acl_status="disabled",
        is_log_target=False,
        versioning="Enabled",
        mfa_delete="Enabled",
        object_lock="Enabled",
        website_hosting=False,
        check_type=S3SecurityScanType.ALL,
    )

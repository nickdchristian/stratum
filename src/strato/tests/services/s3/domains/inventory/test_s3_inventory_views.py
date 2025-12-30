from datetime import datetime

import pytest

from strato.services.s3.domains.inventory.checks import S3InventoryResult
from strato.services.s3.domains.inventory.views import S3InventoryView


@pytest.fixture
def inventory_result():
    return S3InventoryResult(
        resource_arn="arn:aws:s3:::full-bucket",
        resource_name="full-bucket",
        region="us-west-2",
        account_id="999",
        creation_date=datetime(2025, 5, 20),
        encryption_type="aws:kms",
        kms_master_key_id="alias/key",
        bucket_key_enabled=True,
        versioning_status="Enabled",
        mfa_delete="Disabled",
        block_all_public_access=True,
        has_bucket_policy=True,
        bucket_ownership="BucketOwnerEnforced",
        server_access_logging="logs-bucket",
        static_website_hosting="Disabled",
        transfer_acceleration="Enabled",
        intelligent_tiering_config="Enabled",
        object_lock="Enabled",
        object_lock_mode="COMPLIANCE",
        object_lock_retention="1 Year",
        replication_status="Enabled",
        replication_destination="backup-bucket",
        replication_cost_impact="Cross-Region",
        lifecycle_status="Enabled",
        lifecycle_rule_count=5,
        total_bucket_size_gb=500.55,
        total_object_count=10000,
        all_requests_count=50000,
        tags={"Project": "Alpha", "Stage": "Prod"},
    )


def test_get_headers():
    headers = S3InventoryView.get_headers()
    assert len(headers) == 38
    assert headers[0] == "Account ID"
    assert headers[-1] == "Tags"
    assert "Total Size (GB)" in headers


def test_format_csv_row(inventory_result):
    row = S3InventoryView.format_csv_row(inventory_result)

    assert row[2] == "full-bucket"
    assert "2025-05-20" in row[3]
    assert row[4] == "aws:kms"
    assert row[6] == "True"  # Bucket Key
    assert row[9] == "True"  # Public Access
    assert row[24] == "500.55"  # Size
    assert row[25] == "10000"  # Count

    tags_col = row[-1]
    assert "Project=Alpha" in tags_col
    assert "Stage=Prod" in tags_col
    assert "; " in tags_col


def test_format_row_alias(inventory_result):
    """Ensure format_row behaves identically to format_csv_row for this view."""
    csv_row = S3InventoryView.format_csv_row(inventory_result)
    std_row = S3InventoryView.format_row(inventory_result)
    assert csv_row == std_row

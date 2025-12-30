from datetime import datetime

from strato.services.s3.domains.inventory.checks import (
    S3InventoryResult,
    S3InventoryScanner,
)


def test_result_serialization():
    result = S3InventoryResult(
        resource_arn="arn:aws:s3:::bucket",
        resource_name="bucket",
        region="us-east-1",
        account_id="123",
        creation_date=datetime(2025, 1, 1),
        tags={"Env": "Prod"},
    )

    data = result.to_dict()

    assert data["creation_date"] == "2025-01-01T00:00:00"
    assert "findings" not in data
    assert "status" not in data
    assert data["tags"] == {"Env": "Prod"}


def test_scanner_lifecycle_extraction_empty():
    info = S3InventoryScanner._extract_lifecycle_info([])
    assert info["lifecycle_status"] == "Disabled"
    assert info["lifecycle_rule_count"] == 0


def test_scanner_lifecycle_extraction_active():
    rules = [{"ID": "ArchiveRule", "Status": "Enabled"}]
    info = S3InventoryScanner._extract_lifecycle_info(rules)
    assert info["lifecycle_status"] == "Enabled"
    assert info["lifecycle_rule_count"] == 1
    assert info["lifecycle_active_rule_id"] == "ArchiveRule"


def test_scanner_replication_extraction_empty(mocker):
    mock_client = mocker.Mock()
    mock_client.calculate_replication_cost_impact.return_value = "None"

    scanner = S3InventoryScanner()
    scanner.client = mock_client

    info = scanner._extract_replication_info([], "us-east-1")

    assert info["replication_status"] == "Disabled"
    assert info["replication_cost_impact"] is None


def test_scanner_replication_extraction_active(mocker):
    mock_client = mocker.Mock()
    mock_client.calculate_replication_cost_impact.return_value = ["Cross-Region"]

    scanner = S3InventoryScanner()
    scanner.client = mock_client

    rules = [
        {
            "Status": "Enabled",
            "ID": "RepRule",
            "DestinationBucket": "arn:aws:s3:::dest",
            "StorageClass": "Standard",
            "KMSEncrypted": "Enabled",
        }
    ]

    info = scanner._extract_replication_info(rules, "us-east-1")

    assert info["replication_status"] == "Enabled"
    assert info["replication_destination"] == "arn:aws:s3:::dest"
    assert info["replication_kms_encrypted"] is True
    assert info["replication_cost_impact"] == ["Cross-Region"]


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.inventory.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "us-east-1"
    mock_client.get_bucket_tags.return_value = {"Owner": "DevOps"}
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "AES256",
        "BucketKeyEnabled": True,
    }
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": False,
    }
    mock_client.get_bucket_policy.return_value = {"Access": "Private"}
    mock_client.get_public_access_status.return_value = True
    mock_client.get_object_lock_details.return_value = {
        "Status": True,
        "Mode": "GOVERNANCE",
        "Retention": "30 Days",
    }
    mock_client.get_replication_configuration.return_value = []
    mock_client.calculate_replication_cost_impact.return_value = "None"
    mock_client.get_lifecycle_configuration.return_value = []
    mock_client.get_intelligent_tiering_configurations.return_value = ["Config1"]

    mock_client.get_bucket_metrics.return_value = {
        "Storage": {
            "Standard": {"Size": 10.5, "Count": 100},
            "Standard-IA": {"Size": 0, "Count": 0},
            "Intelligent-Tiering": {"Size": 5.0, "Count": 50},
            "RRS": {"Size": 0, "Count": 0},
            "Glacier": {"Size": 0, "Count": 0},
            "Glacier-Deep-Archive": {"Size": 0, "Count": 0},
        },
        "Requests": {"All": 1000, "Get": 800, "Put": 200},
    }

    mock_client.get_acl_status.return_value = {
        "Ownership": "ObjectWriter",
        "Status": "Enabled",
    }
    mock_client.get_logging_status.return_value = "logs-bucket"
    mock_client.get_website_hosting_status.return_value = False
    mock_client.get_accelerate_configuration.return_value = "Suspended"
    mock_client.get_request_payment.return_value = "BucketOwner"
    mock_client.get_cors_count.return_value = 2
    mock_client.get_notification_configuration_count.return_value = 1
    mock_client.get_inventory_configuration_count.return_value = 0
    mock_client.get_analytics_configuration_count.return_value = 0
    mock_client.get_metrics_configuration_count.return_value = 0

    scanner = S3InventoryScanner()
    bucket_data = {"Name": "test-inventory", "CreationDate": datetime(2024, 1, 1)}

    result = scanner.analyze_resource(bucket_data)

    assert isinstance(result, S3InventoryResult)
    assert result.resource_name == "test-inventory"
    assert result.encryption_type == "AES256"
    assert result.bucket_key_enabled is True
    assert result.versioning_status == "Enabled"
    assert result.block_all_public_access is True
    assert result.object_lock
    assert result.intelligent_tiering_config == "Enabled"
    assert result.standard_size_gb == 10.5
    assert result.total_object_count == 150
    assert result.all_requests_count == 1000
    assert result.tags == {"Owner": "DevOps"}

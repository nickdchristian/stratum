from strato.services.rds.domains.inventory.checks import (
    RDSInventoryResult,
    RDSInventoryScanner,
)


def test_result_serialization():
    result = RDSInventoryResult(
        resource_id="db-prod",
        resource_name="db-prod",
        region="us-east-1",
        account_id="123",
        port=5432,
        security_group_ids=["sg-1", "sg-2"],
        option_groups=["default:postgres"],
    )

    data = result.to_dict()

    assert data["resource_id"] == "db-prod"
    assert data["port"] == 5432
    assert "findings" not in data
    assert data["security_group_ids"] == ["sg-1", "sg-2"]
    assert data["option_groups"] == ["default:postgres"]


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.rds.domains.inventory.checks.RDSClient"
    )
    mock_client = mock_client_cls.return_value

    # Mock metric returns (peak, mean)
    mock_client.get_cpu_utilization.return_value = (80.0, 40.0)
    mock_client.get_database_connections.return_value = (100.0, 10.0)
    mock_client.get_read_throughput.return_value = (500.0, 250.0)
    mock_client.get_write_throughput.return_value = (200.0, 100.0)

    scanner = RDSInventoryScanner(account_id="123")

    resource_data = {
        "DBInstanceIdentifier": "db-prod",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-prod",
        "Engine": "postgres",
        "EngineVersion": "14.1",
        "AvailabilityZone": "us-east-1a",
        "DBInstanceClass": "db.t3.medium",
        "PubliclyAccessible": True,
        "MultiAZ": False,
        "StorageType": "gp3",
        "AllocatedStorage": 100,
        "StorageEncrypted": True,
        "Endpoint": {"Port": 5432},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
        "OptionGroupMemberships": [{"OptionGroupName": "default:postgres-14"}],
        "EnabledCloudwatchLogsExports": ["postgresql"],
        "TagList": [{"Key": "Env", "Value": "Prod"}],
    }

    result = scanner.analyze_resource(resource_data)

    assert isinstance(result, RDSInventoryResult)
    assert result.resource_id == "db-prod"
    assert result.engine == "postgres"
    assert result.port == 5432
    assert result.publicly_accessible is True
    assert result.security_group_ids == ["sg-1"]

    assert result.peak_cpu_utilization_90_days == 80.0
    assert result.mean_cpu_utilization_90_days == 40.0

    assert result.peak_database_connections_90_days == 100.0
    assert result.mean_database_connections_90_days == 10.0

    assert result.tags["Env"] == "Prod"

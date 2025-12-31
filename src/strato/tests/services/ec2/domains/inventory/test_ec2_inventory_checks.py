from datetime import datetime

from strato.services.ec2.domains.inventory.checks import (
    EC2InventoryResult,
    EC2InventoryScanner,
)


def test_result_serialization():
    result = EC2InventoryResult(
        resource_id="i-1",
        resource_name="web-01",
        region="us-east-1",
        account_id="123",
        launch_time=datetime(2025, 1, 1),
        security_group_list=["sg-1", "sg-2"],
        highest_memory_14_days=None,
    )

    data = result.to_dict()

    assert data["launch_time"] == "2025-01-01T00:00:00"
    assert "findings" not in data
    assert data["security_group_list"] == ["sg-1", "sg-2"]
    assert data["highest_memory_14_days"] is None


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ec2.domains.inventory.checks.EC2Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.check_optimizer_enrollment.return_value = "Active"
    mock_client.get_volume_details.return_value = {
        "vol-1": {"Encrypted": True, "Size": 50},
        "vol-2": {"Encrypted": False, "Size": 50},
    }
    mock_client.get_image_details.return_value = {
        "Name": "MyAMI",
        "CreationDate": "2024-01-01",
    }
    mock_client.get_cpu_utilization.return_value = 45.0
    mock_client.get_memory_utilization.return_value = None  # Agent missing
    mock_client.get_network_utilization.return_value = 100.0
    mock_client.get_security_group_rules.return_value = {
        "Inbound": ["80", "443"],
        "Outbound": ["All"],
    }
    mock_client.is_instance_managed.return_value = True
    mock_client.get_termination_protection.return_value = False

    scanner = EC2InventoryScanner(account_id="123")
    scanner.optimizer_status = "Active"

    instance_data = {
        "InstanceId": "i-12345",
        "InstanceType": "t3.medium",
        "State": {"Name": "running"},
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "PrivateIpAddress": "10.0.0.1",
        "PublicIpAddress": "1.2.3.4",
        "LaunchTime": datetime(2025, 1, 1),
        "ImageId": "ami-1",
        "VpcId": "vpc-1",
        "BlockDeviceMappings": [
            {"Ebs": {"VolumeId": "vol-1"}},
            {"Ebs": {"VolumeId": "vol-2"}},
        ],
        "SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}],
        "Tags": [{"Key": "Name", "Value": "ProdWeb"}],
    }

    result = scanner.analyze_resource(instance_data)

    assert isinstance(result, EC2InventoryResult)
    assert result.resource_name == "ProdWeb"
    assert result.resource_id == "i-12345"
    assert result.region == "us-east-1"
    assert result.managed is True

    assert result.attached_volumes == 2
    assert result.attached_volume_encryption_status == "Mixed"

    assert result.highest_cpu_14_days == 45.0
    assert result.highest_memory_14_days is None

    assert result.security_groups_count == 2
    assert result.security_group_list == ["sg-1", "sg-2"]
    assert result.security_group_inbound_ports == ["80", "443"]


def test_scanner_optimizer_disabled(mocker):
    mocker.patch("strato.services.ec2.domains.inventory.checks.EC2Client")

    scanner = EC2InventoryScanner()
    scanner.optimizer_status = "Disabled"

    instance_data = {
        "InstanceId": "i-1",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "Tags": [],
    }

    scanner.client.get_image_details.return_value = {}
    scanner.client.get_volume_details.return_value = {}
    scanner.client.get_security_group_rules.return_value = {
        "Inbound": [],
        "Outbound": [],
    }

    result = scanner.analyze_resource(instance_data)

    assert result.rightsizing_recommendation == "OptimizerDisabled"

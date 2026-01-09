import pytest
from botocore.exceptions import ClientError

from strato.services.ec2.client import EC2Client


@pytest.fixture
def ec2_client_wrapper(mocker):
    mocker.patch("boto3.Session")
    return EC2Client()


def test_list_instances(ec2_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
        {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}]},
    ]

    ec2_client_wrapper._client.get_paginator.return_value = mock_paginator

    instances = ec2_client_wrapper.list_instances()
    assert len(instances) == 2
    assert instances[0]["InstanceId"] == "i-1"


def test_get_image_details(ec2_client_wrapper):
    ec2_client_wrapper._client.describe_images.return_value = {
        "Images": [{"Name": "MyAMI", "ImageOwnerAlias": "Self"}]
    }

    details = ec2_client_wrapper.get_image_details("ami-123")
    assert details["Name"] == "MyAMI"
    assert details["OwnerAlias"] == "Self"


def test_get_image_details_empty(ec2_client_wrapper):
    ec2_client_wrapper._client.describe_images.return_value = {"Images": []}
    details = ec2_client_wrapper.get_image_details("ami-123")
    assert details == {}


def test_get_volume_details(ec2_client_wrapper):
    ec2_client_wrapper._client.describe_volumes.return_value = {
        "Volumes": [
            {"VolumeId": "vol-1", "Encrypted": True, "Size": 100, "VolumeType": "gp3"},
            {
                "VolumeId": "vol-2",
                "Encrypted": False,
                "Size": 50,
                "VolumeType": "standard",
            },
        ]
    }

    result = ec2_client_wrapper.get_volume_details(["vol-1", "vol-2"])
    assert result["vol-1"]["Encrypted"] is True
    assert result["vol-2"]["Size"] == 50


def test_get_security_group_rules(ec2_client_wrapper):
    ec2_client_wrapper._client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "IpPermissions": [
                    {"FromPort": 80, "ToPort": 80},  # Single port
                    {"FromPort": 8000, "ToPort": 8010},  # Range
                ],
                "IpPermissionsEgress": [{"FromPort": 443, "ToPort": 443}],
            }
        ]
    }

    result = ec2_client_wrapper.get_security_group_rules(["sg-1"])

    # Sets are unordered, so we check membership
    assert "80" in result["Inbound"]
    assert "8000-8010" in result["Inbound"]
    assert "443" in result["Outbound"]


def test_is_instance_managed_true(ec2_client_wrapper):
    assert ec2_client_wrapper.is_instance_managed("i-1") is True


def test_is_instance_managed_false(ec2_client_wrapper):
    ec2_client_wrapper._ssm_client.describe_instance_information.side_effect = (
        ClientError({"Error": {"Code": "InvalidInstanceId"}}, "op")
    )
    assert ec2_client_wrapper.is_instance_managed("i-1") is False


def test_check_optimizer_enrollment_active(ec2_client_wrapper, mocker):
    mock_opt = mocker.Mock()
    mock_opt.get_enrollment_status.return_value = {"status": "Active"}

    ec2_client_wrapper.session.client.return_value = mock_opt

    status = ec2_client_wrapper.check_optimizer_enrollment()
    assert status == "Active"


def test_get_memory_utilization_no_agent(ec2_client_wrapper):
    ec2_client_wrapper._cw_client.list_metrics.return_value = {"Metrics": []}

    val = ec2_client_wrapper.get_memory_utilization("i-1")
    assert val is None


def test_get_memory_utilization_with_data(ec2_client_wrapper):
    ec2_client_wrapper._cw_client.list_metrics.return_value = {"Metrics": ["exists"]}
    ec2_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": [{"Maximum": 55.5}]
    }

    val = ec2_client_wrapper.get_memory_utilization("i-1")
    assert val == 55.5


def test_get_reserved_instances(ec2_client_wrapper):
    ec2_client_wrapper._client.describe_reserved_instances.return_value = {
        "ReservedInstances": [
            {"ReservedInstancesId": "ri-1", "State": "active"},
            {"ReservedInstancesId": "ri-2", "State": "retired"},
        ]
    }

    ris = ec2_client_wrapper.get_reserved_instances()
    assert len(ris) == 2
    assert ris[0]["ReservedInstancesId"] == "ri-1"
    # Ensure the filter was applied in the call
    ec2_client_wrapper._client.describe_reserved_instances.assert_called_with(
        Filters=[{"Name": "state", "Values": ["active", "retired"]}]
    )

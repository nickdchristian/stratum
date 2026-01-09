from datetime import UTC, datetime, timedelta

from strato.services.ec2.domains.reserved.checks import (
    EC2ReservedInstanceResult,
    EC2ReservedInstanceScanner,
)


def test_result_serialization():
    result = EC2ReservedInstanceResult(
        ri_id="ri-1",
        instance_type="m5.large",
        remaining_days=300,
        resource_arn="arn:aws:ec2:us-east-1:123:reserved-instances/ri-1",
        tags={"Env": "Prod"},
    )

    data = result.to_dict()

    assert data["ri_id"] == "ri-1"
    assert data["instance_type"] == "m5.large"
    assert data["remaining_days"] == 300
    assert data["tags"] == {"Env": "Prod"}
    assert "findings" not in data


def test_scanner_analyze_resource(mocker):
    mocker.patch("strato.services.ec2.domains.reserved.checks.EC2Client")
    scanner = EC2ReservedInstanceScanner(account_id="123")
    scanner.client.session.region_name = "us-east-1"

    start_time = datetime.now(UTC) - timedelta(days=100)
    end_time = datetime.now(UTC) + timedelta(days=265)

    ri_data = {
        "ReservedInstancesId": "ri-123",
        "InstanceType": "m5.large",
        "Scope": "Region",
        "InstanceCount": 5,
        "Start": start_time,
        "End": end_time,
        "Duration": 31536000,
        "OfferingType": "No Upfront",
        "FixedPrice": 0.0,
        "UsagePrice": 0.12,
        "RecurringCharges": [{"Amount": 0.12, "Frequency": "Hourly"}],
        "Tags": [{"Key": "Name", "Value": "Prod-RI"}],
        "State": "active",
    }

    result = scanner.analyze_resource(ri_data)

    assert isinstance(result, EC2ReservedInstanceResult)
    assert result.ri_id == "ri-123"
    assert result.recurring_charges == "0.12/Hourly"

    assert result.tags == {"Name": "Prod-RI"}


def test_scanner_analyze_resource_empty_fields(mocker):
    mocker.patch("strato.services.ec2.domains.reserved.checks.EC2Client")
    scanner = EC2ReservedInstanceScanner(account_id="123")

    ri_data = {
        "ReservedInstancesId": "ri-empty",
        "Start": datetime.now(UTC),
    }

    result = scanner.analyze_resource(ri_data)

    assert result.ri_id == "ri-empty"
    assert result.tags == {}
    assert result.remaining_days == 0

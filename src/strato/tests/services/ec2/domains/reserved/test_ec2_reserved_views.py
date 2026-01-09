from strato.services.ec2.domains.reserved.checks import EC2ReservedInstanceResult
from strato.services.ec2.domains.reserved.views import EC2ReservedInstanceView


def test_get_headers():
    headers = EC2ReservedInstanceView.get_headers()
    assert "id" in headers
    assert "tags" in headers


def test_format_row():
    result = EC2ReservedInstanceResult(
        account_id="123",
        region="us-east-1",
        ri_id="ri-1",
        instance_type="t3.micro",
        instance_count=10,
        term_seconds=31536000,
        remaining_days=365,
        upfront_price=100.50,
        resource_arn="arn:test",
        tags={"Name": "TestRI", "Owner": "DevOps"},
    )

    row = EC2ReservedInstanceView.format_row(result)

    assert row[2] == "ri-1"
    assert "Name=TestRI" in row[20]
    assert "Owner=DevOps" in row[20]

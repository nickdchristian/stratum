from strato.services.rds.domains.reserved.checks import RDSReservedInstanceResult
from strato.services.rds.domains.reserved.views import RDSReservedInstanceView


def test_get_headers():
    headers = RDSReservedInstanceView.get_headers()
    assert "reservation_id" in headers
    assert "lease_id" in headers
    assert "remaining_days" in headers
    # Ensure Inventory headers are NOT present
    assert "db_identifier" not in headers


def test_format_row():
    result = RDSReservedInstanceResult(
        account_id="123",
        region="us-east-1",
        reservation_id="ri-1",
        lease_id="lease-1",
        quantity=5,
        multi_az=True,
        remaining_days=100,
        status="active",
    )

    row = RDSReservedInstanceView.format_row(result)

    assert row[0] == "123"
    assert row[1] == "us-east-1"
    assert row[2] == "ri-1"
    assert row[3] == "lease-1"
    assert row[7] == "active"
    assert row[8] == "True"  # multi_az
    assert row[10] == "100"  # remaining_days
    assert row[11] == "5"  # quantity

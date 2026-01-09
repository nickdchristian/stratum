import pytest

from strato.services.rds.domains.inventory.checks import RDSInventoryResult
from strato.services.rds.domains.inventory.views import RDSInventoryView


@pytest.fixture
def inventory_result():
    return RDSInventoryResult(
        resource_id="db-prod",
        resource_name="db-prod",
        region="us-east-1",
        account_id="999",
        db_identifier="db-prod",
        engine="postgres",
        port=5432,
        security_group_ids=["sg-1", "sg-2"],
        publicly_accessible=False,
        option_groups=["default:postgres"],
        tags={"Env": "Prod"},
    )


def test_get_headers():
    headers = RDSInventoryView.get_headers()
    assert "db_identifier" in headers
    assert "port" in headers
    assert "option_groups" in headers
    # Ensure RI headers are NOT present in standard inventory
    assert "reservation_id" not in headers


def test_format_csv_row(inventory_result):
    row = RDSInventoryView.format_csv_row(inventory_result)

    # Based on the header order in views.py
    # account(0), region(1), db_identifier(2), ...

    assert row[0] == "999"
    assert row[2] == "db-prod"
    assert row[7] == "postgres"
    assert row[11] == "False"  # publicly_accessible
    assert row[13] == "5432"  # port

    # Check joined lists
    assert "sg-1;sg-2" in row[14]
    assert "default:postgres" in row[25]
    assert "Env=Prod" in row[5]

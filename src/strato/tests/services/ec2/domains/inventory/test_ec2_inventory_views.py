from datetime import datetime

import pytest

from strato.services.ec2.domains.inventory.checks import EC2InventoryResult
from strato.services.ec2.domains.inventory.views import EC2InventoryView


@pytest.fixture
def inventory_result():
    return EC2InventoryResult(
        resource_id="i-123",
        resource_name="web-01",
        region="us-east-1",
        account_id="999",
        instance_type="t3.micro",
        state="running",
        launch_time=datetime(2025, 5, 20),
        private_ip="10.0.0.1",
        public_ip4=None,  # Should be empty string
        managed=True,  # Should be "True"
        highest_cpu_14_days=50.5,
        highest_memory_14_days=None,  # Should be empty string
        security_group_list=["sg-1", "sg-2"],  # Should be joined
        tags={"Env": "Prod"},
        rightsizing_recommendation="OptimizerDisabled",
    )


def test_get_headers():
    headers = EC2InventoryView.get_headers()
    assert "instance_id" in headers
    assert "highest_memory_percentage_last_14_days" in headers
    assert "rightsizing_recommendation" in headers


def test_format_csv_row(inventory_result):
    row = EC2InventoryView.format_csv_row(inventory_result)

    # Based on the header order in views.py
    # name (0), account (1), region (2), id (3), type (4), state (5),
    # tags (6), az (7), priv_ip (8), priv_ipv6 (9), pub_ip (10)

    assert row[0] == "web-01"
    assert row[3] == "i-123"
    assert row[10] == ""  # public_ip4 was None
    assert row[14] == "True"  # managed
    assert "2025-05-20" in row[12]  # launch_time
    assert row[27] == "50.5"  # cpu
    assert row[29] == ""  # memory was None

    assert "sg-1;sg-2" in row

    assert "Env=Prod" in row[6]

    assert "OptimizerDisabled" in row

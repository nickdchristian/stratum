import pytest

from strato.services.awslambda.domains.inventory.checks import LambdaInventoryResult
from strato.services.awslambda.domains.inventory.views import LambdaInventoryView


@pytest.fixture
def inventory_result():
    return LambdaInventoryResult(
        resource_arn="arn:aws:lambda:us-east-1:123:function:my-func",
        resource_name="my-func",
        region="us-east-1",
        account_id="123",
        function_aliases=["prod", "dev"],
        memory_size=128,
        layers=["arn:layer:1", "arn:layer:2"],
        environment_variables={"LOG_LEVEL": "DEBUG"},
        tags={"Env": "Prod", "Team": "DevOps"},
        estimated_monthly_cost=10.50,
        success_percentage=99.9,
    )


def test_get_headers():
    headers = LambdaInventoryView.get_headers("INVENTORY")
    assert "function_name" in headers
    assert "estimated_monthly_cost" in headers
    # Index 62 is explicitly verified
    # to prevent regression on the 'tags' column location
    assert headers[62] == "tags"


def test_format_csv_row(inventory_result):
    row = LambdaInventoryView.format_csv_row(inventory_result)

    assert row[0] == "us-east-1"
    assert row[2] == "my-func"
    assert row[11] == "128"
    assert row[21] == "10.5"
    assert row[58] == "99.9"

    assert '["prod", "dev"]' in row
    assert '["arn:layer:1", "arn:layer:2"]' in row
    assert '{"LOG_LEVEL": "DEBUG"}' in row

    # Tags are formatted as 'Key=Value' strings and located at index 62
    assert "Env=Prod; Team=DevOps" in row[62]


def test_format_csv_row_empty_values():
    result = LambdaInventoryResult(
        resource_arn="arn",
        resource_name="func",
        region="us-east-1",
        account_id="123",
        tags=None,
        layers=None,
    )
    row = LambdaInventoryView.format_csv_row(result)

    # Execution role (index 37) and Tags (index 62) should be empty strings
    assert row[37] == ""
    assert row[62] == ""

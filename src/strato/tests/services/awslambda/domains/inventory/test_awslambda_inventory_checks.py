from strato.services.awslambda.domains.inventory.checks import (
    LambdaInventoryResult,
    LambdaInventoryScanner,
)


def test_result_serialization():
    result = LambdaInventoryResult(
        resource_arn="arn:aws:lambda:us-east-1:123:function:my-func",
        resource_name="my-func",
        region="us-east-1",
        runtime="python3.11",
        tags={"Env": "Prod"},
        function_aliases=["prod"],
    )

    data = result.to_dict()

    assert "findings" not in data
    assert "status_score" not in data
    assert data["resource_name"] == "my-func"
    assert data["tags"] == {"Env": "Prod"}
    assert data["function_aliases"] == ["prod"]


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.awslambda.domains.inventory.checks.LambdaClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_function_url_details.return_value = ("https://url", "NONE")
    mock_client.get_tags.return_value = {"Owner": "Platform"}
    mock_client.get_function_aliases.return_value = ["prod"]
    mock_client.get_event_source_mappings.return_value = ["arn:aws:sqs:source"]
    mock_client.get_log_retention.return_value = 14

    mock_client.get_metric_sum.side_effect = lambda metric, *args: {
        "Invocations": 1000000.0,
        "Errors": 100.0,
        "Throttles": 5.0,
    }.get(metric, 0.0)

    mock_client.get_metric_avg.return_value = 500.0
    mock_client.get_metric_max.return_value = 1000.0
    mock_client.get_lambda_insight_metric.return_value = 45.5

    scanner = LambdaInventoryScanner(
        check_type="INVENTORY", session=mocker.Mock(), account_id="123"
    )
    scanner.session.region_name = "us-east-1"

    func_data = {
        "FunctionName": "my-func",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:my-func",
        "Runtime": "python3.11",
        "MemorySize": 1024,
        "Architectures": ["x86_64"],
        "LastModified": "2025-01-01T00:00:00",
        "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-1"]},
        "Layers": [{"Arn": "arn:layer:1"}],
        "Environment": {"Variables": {"LOG_LEVEL": "DEBUG"}},
    }

    result = scanner.analyze_resource(func_data)

    assert isinstance(result, LambdaInventoryResult)
    assert result.resource_name == "my-func"
    assert result.function_url == "https://url"
    assert result.function_url_auth_type == "NONE"
    assert result.success_percentage == 99.99
    assert result.memory_utilization_percentage == 45.5
    assert result.estimated_monthly_cost > 8.5
    assert result.log_retention_days == 14
    assert result.insights_enabled is True


def test_scanner_analyze_resource_arm64_cost(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.awslambda.domains.inventory.checks.LambdaClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_function_url_details.return_value = (None, None)
    mock_client.get_metric_sum.return_value = 1000000.0
    mock_client.get_metric_avg.return_value = 500.0
    mock_client.get_tags.return_value = {}

    scanner = LambdaInventoryScanner(
        check_type="INVENTORY", session=mocker.Mock(), account_id="123"
    )

    func_data = {
        "FunctionName": "arm-func",
        "MemorySize": 1024,
        "Architectures": ["arm64"],
    }

    result = scanner.analyze_resource(func_data)

    # Cost should be lower due to Graviton pricing
    assert result.estimated_monthly_cost < 8.0
    assert result.estimated_monthly_cost > 6.8

import pytest
from botocore.exceptions import ClientError

from strato.services.awslambda.client import LambdaClient


@pytest.fixture
def lambda_client_wrapper(mocker):
    mocker.patch("boto3.Session")
    return LambdaClient()


def test_list_functions(lambda_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"Functions": [{"FunctionName": "func-1"}]},
        {"Functions": [{"FunctionName": "func-2"}]},
    ]

    lambda_client_wrapper._client.get_paginator.return_value = mock_paginator

    functions = lambda_client_wrapper.list_functions()
    assert len(functions) == 2
    assert functions[0]["FunctionName"] == "func-1"


def test_get_function_url_details_success(lambda_client_wrapper):
    lambda_client_wrapper._client.get_function_url_config.return_value = {
        "FunctionUrl": "https://foo",
        "AuthType": "NONE",
    }

    url, auth = lambda_client_wrapper.get_function_url_details("my-func")
    assert url == "https://foo"
    assert auth == "NONE"


def test_get_function_url_details_error(lambda_client_wrapper):
    lambda_client_wrapper._client.get_function_url_config.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "op"
    )

    url, auth = lambda_client_wrapper.get_function_url_details("my-func")
    assert url is None
    assert auth is None


def test_get_function_aliases(lambda_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"Aliases": [{"Name": "prod"}]},
    ]
    lambda_client_wrapper._client.get_paginator.return_value = mock_paginator

    aliases = lambda_client_wrapper.get_function_aliases("my-func")
    assert aliases == ["prod"]


def test_get_metric_sum(lambda_client_wrapper):
    lambda_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": [{"Sum": 500.0}]
    }

    val = lambda_client_wrapper.get_metric_sum("Invocations", "my-func")
    assert val == 500.0


def test_get_metric_sum_no_data(lambda_client_wrapper):
    lambda_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": []
    }

    val = lambda_client_wrapper.get_metric_sum("Invocations", "my-func")
    assert val == 0.0


def test_get_log_retention(lambda_client_wrapper):
    lambda_client_wrapper._logs_client.describe_log_groups.return_value = {
        "logGroups": [{"logGroupName": "/aws/lambda/my-func", "retentionInDays": 7}]
    }

    days = lambda_client_wrapper.get_log_retention("/aws/lambda/my-func")
    assert days == 7


def test_get_log_retention_not_found(lambda_client_wrapper):
    lambda_client_wrapper._logs_client.describe_log_groups.return_value = {
        "logGroups": []
    }

    days = lambda_client_wrapper.get_log_retention("/aws/lambda/my-func")
    assert days == 0

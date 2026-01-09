from unittest import mock

import pytest
from botocore.exceptions import ClientError

from strato.services.rds.client import RDSClient


@pytest.fixture
def rds_client_wrapper(mocker):
    mocker.patch("boto3.Session")
    return RDSClient()


def test_list_instances(rds_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"DBInstances": [{"DBInstanceIdentifier": "db-1"}]},
        {"DBInstances": [{"DBInstanceIdentifier": "db-2"}]},
    ]

    rds_client_wrapper._client.get_paginator.return_value = mock_paginator

    instances = rds_client_wrapper.list_instances()
    assert len(instances) == 2
    assert instances[0]["DBInstanceIdentifier"] == "db-1"


def test_get_reserved_instances(rds_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"ReservedDBInstances": [{"ReservedDBInstanceId": "ri-1"}]},
        {"ReservedDBInstances": [{"ReservedDBInstanceId": "ri-2"}]},
    ]

    rds_client_wrapper._client.get_paginator.return_value = mock_paginator

    ris = rds_client_wrapper.get_reserved_instances()
    assert len(ris) == 2
    assert ris[0]["ReservedDBInstanceId"] == "ri-1"


def test_get_metric_stats_success(rds_client_wrapper):
    rds_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": [
            {"Maximum": 50.0, "Average": 25.0},
            {"Maximum": 100.0, "Average": 50.0},
        ]
    }

    peak, mean = rds_client_wrapper.get_cpu_utilization("db-1")

    assert peak == 100.0
    assert mean == 37.5


def test_get_metric_stats_empty(rds_client_wrapper):
    rds_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": []
    }

    peak, mean = rds_client_wrapper.get_cpu_utilization("db-1")

    assert peak == 0.0
    assert mean == 0.0


def test_get_metric_stats_error(rds_client_wrapper):
    rds_client_wrapper._cw_client.get_metric_statistics.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "get_metric_statistics"
    )

    peak, mean = rds_client_wrapper.get_cpu_utilization("db-1")

    assert peak == 0.0
    assert mean == 0.0


def test_specific_metric_methods(rds_client_wrapper):
    """
    Ensure the wrapper methods call the
    generic _get_metric_stats with correct parameters.
    """
    with mock.patch.object(
        rds_client_wrapper, "_get_metric_stats", return_value=(10.0, 5.0)
    ) as mock_stats:
        rds_client_wrapper.get_database_connections("db-1")
        mock_stats.assert_called_with(
            "AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", "db-1", 90
        )

        rds_client_wrapper.get_write_throughput("db-1")
        mock_stats.assert_called_with(
            "AWS/RDS", "WriteThroughput", "DBInstanceIdentifier", "db-1", 90
        )

        rds_client_wrapper.get_read_throughput("db-1")
        mock_stats.assert_called_with(
            "AWS/RDS", "ReadThroughput", "DBInstanceIdentifier", "db-1", 90
        )

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from strato.services.s3.client import S3Client


@pytest.fixture
def s3_client():
    mock_session = MagicMock()
    return S3Client(session=mock_session)


def test_policy_parser_detects_cloudtrail_string(s3_client):
    """Test parsing when Principal is a simple dict with a string."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ]
    }

    s3_client._client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

    result = s3_client.get_bucket_policy("my-bucket")

    assert "cloudtrail.amazonaws.com" in result["Log_Sources"]
    assert len(result["Log_Sources"]) == 1


def test_policy_parser_detects_multiple_services_list(s3_client):
    """Test parsing when Principal is a list of services."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": ["cloudtrail.amazonaws.com", "config.amazonaws.com"]
                },
                "Action": "s3:PutObject",
            }
        ]
    }

    s3_client._client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

    result = s3_client.get_bucket_policy("my-bucket")

    assert "cloudtrail.amazonaws.com" in result["Log_Sources"]
    assert "config.amazonaws.com" in result["Log_Sources"]
    assert len(result["Log_Sources"]) == 2


def test_policy_parser_ignores_unrelated_services(s3_client):
    """Test that unrelated services (e.g. lambda) are not flagged as log sources."""
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "s3:GetObject",
            }
        ]
    }

    s3_client._client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

    result = s3_client.get_bucket_policy("my-bucket")

    assert len(result["Log_Sources"]) == 0


def test_policy_parser_handles_wildcard_principal(s3_client):
    """
    Test that wildcard principals mark access as Public but don't crash log parser.
    """
    policy = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
    }

    s3_client._client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}

    result = s3_client.get_bucket_policy("my-bucket")

    assert result["Access"] == "Public"
    assert len(result["Log_Sources"]) == 0


def test_policy_parser_handles_no_policy(s3_client):
    """Test graceful handling of NoSuchBucketPolicy."""
    error = ClientError({"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy")
    s3_client._client.get_bucket_policy.side_effect = error

    result = s3_client.get_bucket_policy("my-bucket")

    assert result["Access"] == "Private"
    assert result["Log_Sources"] == []

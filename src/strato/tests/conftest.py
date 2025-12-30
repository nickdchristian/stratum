import os

import boto3
import pytest
from moto import mock_aws

from strato.services.s3.client import S3Client


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def s3_mock(aws_credentials):
    with mock_aws():
        yield boto3.client("s3", region_name="us-east-1")


@pytest.fixture(scope="function")
def sts_mock(aws_credentials):
    with mock_aws():
        yield boto3.client("sts", region_name="us-east-1")


@pytest.fixture(scope="function")
def org_mock(aws_credentials):
    with mock_aws():
        yield boto3.client("organizations", region_name="us-east-1")


@pytest.fixture
def s3_client_wrapper(s3_mock):
    return S3Client()

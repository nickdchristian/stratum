import json

from botocore.exceptions import ClientError


def test_list_buckets(s3_client_wrapper, s3_mock):
    s3_mock.create_bucket(Bucket="test-bucket-1")
    s3_mock.create_bucket(Bucket="test-bucket-2")

    buckets = s3_client_wrapper.list_buckets()
    assert len(buckets) == 2
    assert buckets[0]["Name"] == "test-bucket-1"


def test_get_bucket_region(s3_client_wrapper, s3_mock):
    s3_mock.create_bucket(
        Bucket="eu-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    region = s3_client_wrapper.get_bucket_region("eu-bucket")
    assert region == "eu-central-1"


def test_get_public_access_status(s3_client_wrapper, s3_mock):
    bucket = "public-block-bucket"
    s3_mock.create_bucket(Bucket=bucket)

    assert s3_client_wrapper.get_public_access_status(bucket) is False

    s3_mock.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert s3_client_wrapper.get_public_access_status(bucket) is True


def test_get_bucket_policy_ssl_enforcement(s3_client_wrapper, s3_mock):
    bucket = "ssl-bucket"
    s3_mock.create_bucket(Bucket=bucket)

    secure_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }

    s3_mock.put_bucket_policy(Bucket=bucket, Policy=json.dumps(secure_policy))

    result = s3_client_wrapper.get_bucket_policy(bucket)
    assert result["SSL_Enforced"] is True
    assert result["Access"] == "Private"


def test_get_encryption_status_kms(s3_client_wrapper, s3_mock):
    bucket = "enc-bucket"
    s3_mock.create_bucket(Bucket=bucket)

    s3_mock.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/my-key",
                    }
                }
            ]
        },
    )

    status = s3_client_wrapper.get_encryption_status(bucket)
    assert status["SSEAlgorithm"] == "aws:kms"
    assert status["KMSMasterKeyID"] == "alias/my-key"


def test_safe_aws_call_decorator(s3_client_wrapper, mocker):
    mocker.patch.object(
        s3_client_wrapper._client,
        "get_bucket_versioning",
        side_effect=ClientError({"Error": {"Code": "AccessDenied"}}, "operation"),
    )

    result = s3_client_wrapper.get_versioning_status("locked-bucket")
    assert result["Status"] is None
    assert result["MFADelete"] is False

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class S3Client:
    """
    Wrapper for Boto3 S3 interactions.

    Handles:
    - Pagination
    - Adaptive Retries (to handle throttling)
    - Error suppression (returns defaults on missing permissions/configs)
    """

    def __init__(self):
        # Adaptive mode helps with rate limiting during multi-threaded scans
        retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self._client = boto3.client("s3", config=retry_config)

    def list_buckets(self) -> list[dict]:
        """Lists all buckets in the account using pagination."""
        paginator = self._client.get_paginator("list_buckets")
        buckets = []
        for page in paginator.paginate():
            buckets.extend(page.get("Buckets", []))

        return buckets

    def get_bucket_region(self, bucket_name: str) -> str:
        """Resolves bucket region."""
        try:
            response = self._client.get_bucket_location(Bucket=bucket_name)
            return response.get("LocationConstraint") or "us-east-1"
        except ClientError:
            return "unknown"

    def get_public_access_status(self, bucket_name: str) -> bool:
        """
        Checks if the bucket has Public Access Block enabled.
        """
        try:
            response = self._client.get_public_access_block(Bucket=bucket_name)
            public_access_config = response.get("PublicAccessBlockConfiguration", {})
            return all(
                [
                    public_access_config.get("BlockPublicAcls", False),
                    public_access_config.get("IgnorePublicAcls", False),
                    public_access_config.get("BlockPublicPolicy", False),
                    public_access_config.get("RestrictPublicBuckets", False),
                ]
            )
        except ClientError:
            # If we can't read the config, assume it's not blocked (fail safe)
            return False

    def get_encryption_status(self, bucket_name: str) -> str:
        """
        Checks for default server-side encryption.
        """
        try:
            response = self._client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            if not rules:
                return "None"

            encryption_type = (
                rules[0]
                .get("ApplyServerSideEncryptionByDefault", {})
                .get("SSEAlgorithm")
            )
            return encryption_type or "Unknown"
        except ClientError:
            return "None"

from strato.services.s3.domains.inventory.checks import S3InventoryResult


class S3InventoryView:
    @classmethod
    def get_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return cls.get_csv_headers(check_type)

    @classmethod
    def get_csv_headers(cls, check_type: str = "INVENTORY") -> list[str]:
        return [
            "Account ID",
            "Region",
            "Bucket Name",
            "Creation Date",
            "Encryption",
            "KMS Key ID",
            "Bucket Key",
            "Versioning",
            "MFA Delete",
            "Public Access Blocked",
            "Bucket Policy",
            "Ownership",
            "Logging",
            "Website Hosting",
            "Transfer Accel",
            "Intelligent-Tiering",
            "Object Lock",
            "Lock Mode",
            "Lock Retention",
            "Replication Status",
            "Replication Dest",
            "Repl Cost Impact",
            "Lifecycle Status",
            "Lifecycle Rules",
            "Total Size (GB)",
            "Total Objects",
            "Requests (All)",
            "Requests (Get)",
            "Requests (Put)",
            "Standard (GB)",
            "Standard-IA (GB)",
            "Intelligent-Tiering (GB)",
            "Glacier (GB)",
            "Deep Archive (GB)",
            "RRS (GB)",
            "Glacier Obj Count",
            "Deep Archive Obj Count",
            "Tags",
        ]

    @classmethod
    def format_row(cls, result: S3InventoryResult) -> list[str]:
        return cls.format_csv_row(result)

    @classmethod
    def format_csv_row(cls, result: S3InventoryResult) -> list[str]:
        tags_string = "; ".join(f"{key}={value}" for key, value in result.tags.items())

        creation_string = (
            result.creation_date.isoformat() if result.creation_date else ""
        )

        return [
            result.account_id,
            result.region,
            result.resource_name,
            creation_string,
            result.encryption_type,
            result.kms_master_key_id,
            str(result.bucket_key_enabled),
            result.versioning_status,
            result.mfa_delete,
            str(result.block_all_public_access),
            str(result.has_bucket_policy),
            result.bucket_ownership,
            result.server_access_logging,
            result.static_website_hosting,
            result.transfer_acceleration,
            result.intelligent_tiering_config,
            result.object_lock,
            result.object_lock_mode,
            result.object_lock_retention,
            result.replication_status,
            result.replication_destination,
            result.replication_cost_impact,
            result.lifecycle_status,
            str(result.lifecycle_rule_count),
            str(result.total_bucket_size_gb),
            str(result.total_object_count),
            str(result.all_requests_count),
            str(result.get_requests_count),
            str(result.put_requests_count),
            str(result.standard_size_gb),
            str(result.standard_ia_size_gb),
            str(result.intelligent_tiering_size_gb),
            str(result.glacier_size_gb),
            str(result.deep_archive_size_gb),
            str(result.rrs_size_gb),
            str(result.glacier_object_count),
            str(result.deep_archive_object_count),
            tags_string,
        ]

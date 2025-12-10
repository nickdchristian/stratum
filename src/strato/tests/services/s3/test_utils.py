import unittest

from strato.services.s3.utils import get_bucket_name_predictability


class TestS3Utils(unittest.TestCase):
    def test_predictability_high_risk_short_names(self):
        """Test that short names are always flagged as HIGH predictability."""
        # Even if random, < 8 chars is easily brute-forced
        self.assertEqual(get_bucket_name_predictability("abc"), "HIGH")
        self.assertEqual(get_bucket_name_predictability("x7z"), "HIGH")

    def test_predictability_high_risk_low_entropy(self):
        # "aaaaaaaa" has 0 entropy.
        # "bucketbucket" was ~2.58 entropy (just barely Moderate).
        self.assertEqual(get_bucket_name_predictability("aaaaaaaa"), "HIGH")
        self.assertEqual(get_bucket_name_predictability("abababab"), "HIGH")

    def test_predictability_low_risk_guid(self):
        """Test that names with GUIDs/Hex fragments are LOW predictability."""
        # 8+ hex chars + high entropy
        guid_bucket = "strato-logs-3a9f1c4d"
        self.assertEqual(get_bucket_name_predictability(guid_bucket), "LOW")

        # Full UUID
        uuid_bucket = "company-assets-550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(get_bucket_name_predictability(uuid_bucket), "LOW")

    def test_predictability_moderate(self):
        """Test standard dictionary words fall into MODERATE."""
        # "marketing-assets" is predictable, but long enough to avoid "HIGH"
        # and lacks a GUID to be "LOW".
        self.assertEqual(get_bucket_name_predictability("marketing-assets"), "MODERATE")
        self.assertEqual(
            get_bucket_name_predictability("production-backup-2024"), "MODERATE"
        )

    def test_regex_edge_cases(self):
        """Ensure the regex strictly catches hex fragments."""
        # "abcdefgh" contains 'g' and 'h', so it is NOT valid hex.
        # It should likely fall to MODERATE or HIGH depending on entropy,
        # but definitely NOT LOW (which requires hex regex match).

        # 'abcdefgh' length 8. entropy is high (all distinct).
        # But has_guid_fragment will be False (g/h are not hex).
        # So it should be MODERATE.
        self.assertNotEqual(get_bucket_name_predictability("abcdefgh"), "LOW")

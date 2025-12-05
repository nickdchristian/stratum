from strato.core.scoring import RiskWeight
from strato.services.s3.domains.security import S3SecurityScanType


def test_s3_safe(base_s3_result):
    assert base_s3_result.risk_score == RiskWeight.NONE
    assert base_s3_result.risk_level == "SAFE"


def test_s3_public_access_risk(base_s3_result):
    base_s3_result.public_access_blocked = False
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.CRITICAL
    assert "Public Access Allowed" in base_s3_result.risk_reasons


def test_s3_encryption_risk(base_s3_result):
    base_s3_result.encryption = "None"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.MEDIUM
    assert "Encryption Missing" in base_s3_result.risk_reasons


def test_s3_mixed_risk(base_s3_result):
    base_s3_result.public_access_blocked = False
    base_s3_result.encryption = "None"
    base_s3_result._evaluate_risk()

    # Scores should stack
    expected_score = RiskWeight.CRITICAL + RiskWeight.MEDIUM
    assert base_s3_result.risk_score == expected_score
    assert len(base_s3_result.risk_reasons) == 2


def test_s3_check_type_filtering(base_s3_result):
    # If we ONLY scan for encryption, public access failure should be ignored
    base_s3_result.check_type = S3SecurityScanType.ENCRYPTION
    base_s3_result.public_access_blocked = (
        False  # This is a critical risk, but out of scope
    )
    base_s3_result.encryption = "AES256"
    base_s3_result._evaluate_risk()

    assert base_s3_result.risk_score == RiskWeight.NONE

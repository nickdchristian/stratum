from strato.core.scoring import RiskWeight


def test_risk_weights_integrity():
    assert RiskWeight.CRITICAL == 100
    assert RiskWeight.HIGH == 50
    assert RiskWeight.MEDIUM == 20
    assert RiskWeight.LOW == 5
    assert RiskWeight.NONE == 0

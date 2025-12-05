from strato.core.models import AuditResult


def test_risk_level_mapping():
    r1 = AuditResult("arn", "res", "us-east-1", risk_score=100)
    assert r1.risk_level == "CRITICAL"
    assert r1.has_risk is True

    r2 = AuditResult("arn", "res", "us-east-1", risk_score=50)
    assert r2.risk_level == "HIGH"

    r3 = AuditResult("arn", "res", "us-east-1", risk_score=20)
    assert r3.risk_level == "MEDIUM"

    r4 = AuditResult("arn", "res", "us-east-1", risk_score=5)
    assert r4.risk_level == "LOW"

    r5 = AuditResult("arn", "res", "us-east-1", risk_score=0)
    assert r5.risk_level == "SAFE"
    assert r5.has_risk is False


def test_row_rendering():
    result = AuditResult(
        resource_arn="arn:aws:test",
        resource_name="test-res",
        region="us-east-1",
        risk_score=100,
        risk_reasons=["Bad Config"],
    )

    table_row = result.get_table_row()
    assert "test-res" in table_row
    assert "[red]CRITICAL[/red]" in table_row[2]

    # CSV row should be clean
    csv_row = result.get_csv_row()
    assert "CRITICAL" in csv_row[2]
    assert "[red]" not in csv_row[2]

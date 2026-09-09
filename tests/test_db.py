import pytest
from soc_toolkit.db import init_db, get_alerts, insert_alert, get_incidents, insert_incident

def test_db_init_and_seed():
    init_db()
    alerts = get_alerts()
    assert len(alerts) >= 2
    incidents = get_incidents()
    assert len(incidents) >= 1

def test_insert_alert():
    init_db()
    alert_id = insert_alert(
        rule_id="TEST_RULE",
        severity="MEDIUM",
        title="Test Alert Title",
        description="Test description",
        evidence="Test evidence",
        mitre_technique="T1000",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1"
    )
    assert alert_id > 0
    alerts = get_alerts(limit=10)
    assert any(a["id"] == alert_id for a in alerts)

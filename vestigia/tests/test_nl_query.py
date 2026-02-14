import pytest
from datetime import datetime, UTC, timedelta

from core.nl_query import NLQueryEngine
from core.ledger_engine import StructuredEvidence


def test_nl_query_parsing_basic():
    engine = NLQueryEngine()
    parsed = engine.parse("show high risk events for agent-9 last week")
    assert parsed["filters"]["actor_id"] == "agent-9"
    assert "start_date" in parsed["filters"]
    assert parsed["post_filters"]["min_anomaly_risk"] == 70


def test_nl_query_apply_off_hours(populated_ledger):
    # Insert an off-hours event with anomaly risk
    event = populated_ledger.append_event(
        actor_id="agent-001",
        action_type="SECURITY_SCAN",
        status="WARNING",
        evidence={"summary": "off-hours", "anomaly_risk": 80},
    )
    engine = NLQueryEngine()
    parsed = engine.parse("off hours high risk for agent-001")
    events = populated_ledger.query_events(actor_id="agent-001", limit=50)
    results = engine.apply([e.__dict__ for e in events], parsed["post_filters"])
    assert any(r["event_id"] == event.event_id for r in results)

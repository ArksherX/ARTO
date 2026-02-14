"""Tests for core/enrichment_service.py — enrichment, risk scoring, SIEM webhooks."""

import pytest
from datetime import datetime, UTC, timedelta
from unittest.mock import MagicMock

from core.enrichment_service import EnrichmentService, EnrichmentResult


@pytest.fixture
def svc():
    return EnrichmentService()


@pytest.fixture
def svc_with_ledger(ledger):
    return EnrichmentService(ledger=ledger)


# ------------------------------------------------------------------
# Event enrichment
# ------------------------------------------------------------------


class TestEventEnrichment:
    def test_enrich_adds_fields(self, svc):
        event = {
            "actor_id": "agent-1",
            "action_type": "TOOL_EXECUTION",
            "status": "SUCCESS",
            "evidence": {"summary": "test", "metadata": {"ip": "192.168.1.42"}},
        }
        enriched = svc.enrich_event(event)
        evi = enriched["evidence"]
        assert "enrichment" in evi
        assert "geo" in evi["enrichment"]
        assert evi["enrichment"]["geo"]["country"] == "PRIVATE"

    def test_enrich_without_ip(self, svc):
        event = {
            "actor_id": "agent-1",
            "action_type": "HEARTBEAT",
            "status": "SUCCESS",
            "evidence": {"summary": "no ip here"},
        }
        enriched = svc.enrich_event(event)
        assert "enrichment" in enriched["evidence"]

    def test_ioc_detection(self, svc):
        event = {
            "actor_id": "agent-1",
            "action_type": "TOOL_EXECUTION",
            "status": "SUCCESS",
            "evidence": {"summary": "Accessed evil.example.com"},
        }
        enriched = svc.enrich_event(event)
        iocs = enriched["evidence"]["enrichment"].get("ioc_matches", [])
        assert len(iocs) >= 1
        assert any("evil.example.com" in m["indicator"] for m in iocs)

    def test_actor_context_built(self, svc):
        event = {
            "actor_id": "agent-007",
            "action_type": "TOKEN_ISSUED",
            "status": "SUCCESS",
            "evidence": {"summary": "test"},
        }
        svc.enrich_event(event)
        svc.enrich_event(event)
        ctx = svc._actor_cache["agent-007"]
        assert len(ctx) == 2

    def test_stats_increment(self, svc):
        svc.enrich_event({"actor_id": "a", "evidence": {"summary": "x"}})
        assert svc.get_stats()["events_enriched"] == 1


# ------------------------------------------------------------------
# Risk scoring
# ------------------------------------------------------------------


class TestRiskScoring:
    def test_no_history_returns_zero(self, svc):
        result = svc.calculate_risk_score("unknown-actor")
        assert result["score"] == 0.0
        assert "no_history" in result["factors"]

    def test_critical_events_increase_score(self, svc):
        now = datetime.now(UTC).isoformat()
        svc._actor_cache["risky"] = [
            {"timestamp": now, "action_type": "THREAT_DETECTED", "status": "CRITICAL"},
            {"timestamp": now, "action_type": "ACTION_BLOCKED", "status": "BLOCKED"},
            {"timestamp": now, "action_type": "HEARTBEAT", "status": "SUCCESS"},
        ]
        result = svc.calculate_risk_score("risky")
        assert result["score"] > 0

    def test_high_failure_ratio(self, svc):
        now = datetime.now(UTC).isoformat()
        svc._actor_cache["failing"] = [
            {"timestamp": now, "action_type": "X", "status": "BLOCKED"},
            {"timestamp": now, "action_type": "X", "status": "CRITICAL"},
            {"timestamp": now, "action_type": "X", "status": "BLOCKED"},
        ]
        result = svc.calculate_risk_score("failing")
        assert any("failure_ratio" in f for f in result["factors"])

    def test_score_capped_at_100(self, svc):
        now = datetime.now(UTC).isoformat()
        svc._actor_cache["extreme"] = [
            {"timestamp": now, "action_type": "X", "status": "CRITICAL"}
            for _ in range(200)
        ]
        result = svc.calculate_risk_score("extreme")
        assert result["score"] <= 100.0


# ------------------------------------------------------------------
# SIEM webhook handling
# ------------------------------------------------------------------


class TestSIEMWebhook:
    def test_handle_webhook_without_ledger(self, svc):
        payload = {
            "source": "splunk",
            "alert_id": "alert-001",
            "description": "Suspicious activity",
            "severity": "high",
        }
        result = svc.handle_siem_webhook(payload)
        assert result["status"] == "processed"
        assert result["alert_id"] == "alert-001"
        assert svc.get_stats()["webhooks_processed"] == 1

    def test_handle_webhook_with_ledger(self, svc_with_ledger):
        payload = {
            "source": "elastic",
            "alert_id": "alert-002",
            "description": "Anomaly",
            "severity": "medium",
            "affected_events": ["nonexistent-1"],
        }
        result = svc_with_ledger.handle_siem_webhook(payload)
        assert result["status"] == "processed"


# ------------------------------------------------------------------
# Correlation
# ------------------------------------------------------------------


class TestCorrelation:
    def test_correlate_without_ledger(self, svc):
        result = svc.correlate_events(actor_id="agent-1")
        assert result == []

    def test_correlate_with_ledger(self, svc_with_ledger):
        # Add an event through ledger
        svc_with_ledger.ledger.append_event(
            "corr-agent", "HEARTBEAT", "SUCCESS", "correlation test"
        )
        result = svc_with_ledger.correlate_events(actor_id="corr-agent")
        assert len(result) >= 1


# ------------------------------------------------------------------
# GeoIP and helpers
# ------------------------------------------------------------------


class TestHelpers:
    def test_geoip_private_ip(self, svc):
        result = svc._geoip_lookup("192.168.1.1")
        assert result["country"] == "PRIVATE"

    def test_geoip_unknown_ip(self, svc):
        result = svc._geoip_lookup("8.8.8.8")
        assert result["country"] == "UNKNOWN"

    def test_extract_ip_from_evidence(self, svc):
        event = {"evidence": {"ip": "10.0.0.1"}}
        assert svc._extract_ip(event) == "10.0.0.1"

    def test_extract_ip_from_metadata(self, svc):
        event = {"evidence": {"metadata": {"client_ip": "172.16.0.1"}}}
        assert svc._extract_ip(event) == "172.16.0.1"

    def test_extract_ip_none(self, svc):
        event = {"evidence": {"summary": "no ip"}}
        assert svc._extract_ip(event) is None

    def test_parse_timestamp(self, svc):
        dt = svc._parse_ts("2025-01-15T10:30:00+00:00")
        assert dt.year == 2025
        assert dt.month == 1

    def test_off_hours_detection(self, svc):
        # 3 AM is off-hours
        assert svc._is_off_hours("2025-01-15T03:00:00+00:00") is True
        # Noon is not off-hours on a weekday
        # Jan 15, 2025 is a Wednesday
        assert svc._is_off_hours("2025-01-15T12:00:00+00:00") is False


# ------------------------------------------------------------------
# Start / stop
# ------------------------------------------------------------------


class TestLifecycle:
    def test_start_stop(self, svc):
        svc.start()
        assert svc._running is True
        svc.stop()
        assert svc._running is False

    def test_double_start(self, svc):
        svc.start()
        svc.start()  # should not raise
        svc.stop()

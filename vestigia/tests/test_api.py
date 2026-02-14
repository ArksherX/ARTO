"""Tests for api_server.py — FastAPI endpoints."""

import os
import json
import pytest

# Ensure no API key is required during tests
os.environ["VESTIGIA_API_KEY"] = ""
os.environ["VESTIGIA_ENABLE_ANCHORING"] = "false"

from fastapi.testclient import TestClient


@pytest.fixture
def api_client(tmp_ledger_path, monkeypatch):
    """TestClient wired to a temporary ledger."""
    monkeypatch.setenv("VESTIGIA_LEDGER_PATH", tmp_ledger_path)
    monkeypatch.setenv("VESTIGIA_API_KEY", "")

    import api_server
    api_server._ledger = None  # force re-init
    api_server.LEDGER_PATH = tmp_ledger_path
    api_server.API_KEY = ""
    # Reset rate limiter to avoid cross-test exhaustion
    api_server.rate_limiter = api_server.TokenBucket(rate=10.0, capacity=20.0)

    client = TestClient(api_server.app)
    return client


@pytest.fixture
def authed_client(tmp_ledger_path, monkeypatch):
    """TestClient with API key auth enabled."""
    monkeypatch.setenv("VESTIGIA_LEDGER_PATH", tmp_ledger_path)
    monkeypatch.setenv("VESTIGIA_API_KEY", "test-secret-key")

    import api_server
    api_server._ledger = None
    api_server.LEDGER_PATH = tmp_ledger_path
    api_server.API_KEY = "test-secret-key"
    api_server.rate_limiter = api_server.TokenBucket(rate=10.0, capacity=20.0)

    client = TestClient(api_server.app)
    return client


class TestHealthEndpoint:
    def test_health_returns_200(self, api_client):
        resp = api_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "total_events" in data
        assert data["ledger_valid"] is True

    def test_health_no_auth_required(self, authed_client):
        resp = authed_client.get("/health")
        assert resp.status_code == 200


class TestEventIngestion:
    def test_create_event(self, api_client):
        payload = {
            "actor_id": "agent-1",
            "action_type": "TOOL_EXECUTION",
            "status": "SUCCESS",
            "evidence": {"summary": "test event"},
        }
        resp = api_client.post("/events", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "recorded"
        assert "event_id" in data
        assert "integrity_hash" in data

    def test_create_event_with_trace(self, api_client):
        payload = {
            "actor_id": "agent-1",
            "action_type": "SECURITY_SCAN",
            "status": "SUCCESS",
            "evidence": {"summary": "scan ok"},
            "trace_id": "abc123",
            "span_id": "def456",
            "severity": "LOW",
        }
        resp = api_client.post("/events", json=payload)
        assert resp.status_code == 201

    def test_create_event_missing_fields(self, api_client):
        resp = api_client.post("/events", json={"actor_id": "a"})
        assert resp.status_code == 422


class TestEventQuery:
    def test_list_events(self, api_client):
        # Ingest some events first
        for i in range(3):
            api_client.post("/events", json={
                "actor_id": f"agent-{i}",
                "action_type": "HEARTBEAT",
                "status": "SUCCESS",
                "evidence": {"summary": f"ev-{i}"},
            })
        resp = api_client.get("/events")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert data["total"] >= 3

    def test_filter_by_actor(self, api_client):
        api_client.post("/events", json={
            "actor_id": "unique-actor",
            "action_type": "TOKEN_ISSUED",
            "status": "SUCCESS",
            "evidence": {"summary": "unique"},
        })
        resp = api_client.get("/events", params={"actor_id": "unique-actor"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_pagination(self, api_client):
        for i in range(5):
            api_client.post("/events", json={
                "actor_id": "a",
                "action_type": "HEARTBEAT",
                "status": "SUCCESS",
                "evidence": {"summary": f"p-{i}"},
            })
        resp = api_client.get("/events", params={"limit": 2, "offset": 0})
        assert resp.status_code == 200
        assert len(resp.json()["events"]) <= 2


class TestGetEvent:
    def test_get_existing_event(self, api_client):
        create_resp = api_client.post("/events", json={
            "actor_id": "lookup-test",
            "action_type": "TOKEN_ISSUED",
            "status": "SUCCESS",
            "evidence": {"summary": "lookup test"},
        })
        event_id = create_resp.json()["event_id"]
        resp = api_client.get(f"/events/{event_id}")
        assert resp.status_code == 200
        assert resp.json()["event_id"] == event_id

    def test_get_nonexistent_event(self, api_client):
        resp = api_client.get("/events/nonexistent-id-12345")
        assert resp.status_code == 404


class TestBatchIngestion:
    def test_batch_create(self, api_client):
        payload = {
            "events": [
                {
                    "actor_id": "batch-1",
                    "action_type": "HEARTBEAT",
                    "status": "SUCCESS",
                    "evidence": {"summary": "b1"},
                },
                {
                    "actor_id": "batch-2",
                    "action_type": "TOKEN_ISSUED",
                    "status": "SUCCESS",
                    "evidence": {"summary": "b2"},
                },
            ]
        }
        resp = api_client.post("/events/batch", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["recorded"] == 2
        assert data["failed"] == 0


class TestIntegrityEndpoint:
    def test_integrity_check(self, api_client):
        resp = api_client.get("/integrity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is True
        assert "total_entries" in data


class TestStatisticsEndpoint:
    def test_statistics(self, api_client):
        resp = api_client.get("/statistics")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_events" in data


class TestSIEMWebhook:
    def test_siem_webhook(self, api_client):
        payload = {
            "source": "splunk",
            "alert_id": "alert-001",
            "severity": "HIGH",
            "description": "Suspicious activity detected",
        }
        resp = api_client.post("/webhooks/siem", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "recorded"
        assert "enriched_event_id" in data


class TestAuth:
    def test_no_auth_blocks(self, authed_client):
        resp = authed_client.post("/events", json={
            "actor_id": "a",
            "action_type": "HEARTBEAT",
            "status": "SUCCESS",
            "evidence": {"summary": "test"},
        })
        assert resp.status_code == 401

    def test_wrong_token(self, authed_client):
        resp = authed_client.post(
            "/events",
            json={
                "actor_id": "a",
                "action_type": "HEARTBEAT",
                "status": "SUCCESS",
                "evidence": {"summary": "test"},
            },
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_correct_token(self, authed_client):
        resp = authed_client.post(
            "/events",
            json={
                "actor_id": "a",
                "action_type": "HEARTBEAT",
                "status": "SUCCESS",
                "evidence": {"summary": "test"},
            },
            headers={"Authorization": "Bearer test-secret-key"},
        )
        assert resp.status_code == 201


class TestPhase5Endpoints:
    def test_nl_query(self, api_client):
        api_client.post("/events", json={
            "actor_id": "agent-9",
            "action_type": "SECURITY_SCAN",
            "status": "WARNING",
            "evidence": {"summary": "alert", "anomaly_risk": 80},
        })
        resp = api_client.post("/nl/query", json={"query": "high risk events for agent-9", "limit": 50})
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data

    def test_playbook_execute(self, api_client):
        resp = api_client.post("/playbooks/execute", json={
            "name": "compromised_agent",
            "actor_id": "agent-1",
            "action_type": "SECURITY_SCAN",
            "status": "WARNING",
            "risk_score": 95,
        })
        assert resp.status_code == 200
        assert resp.json()["playbook_name"] == "compromised_agent"

    def test_risk_forecast(self, api_client):
        for i in range(5):
            api_client.post("/events", json={
                "actor_id": "agent-forecast",
                "action_type": "HEARTBEAT",
                "status": "SUCCESS",
                "evidence": {"summary": f"ev-{i}"},
            })
        resp = api_client.get("/risk/forecast", params={"actor_id": "agent-forecast", "horizon_hours": 24})
        assert resp.status_code == 200
        assert "predicted_risk" in resp.json()

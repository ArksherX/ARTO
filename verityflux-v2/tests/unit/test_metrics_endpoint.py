"""
Tests for VerityFlux's Prometheus /metrics endpoint.

Tessera and Vestigia have both exposed /metrics for some time; VerityFlux did
not. A Prometheus configuration written on the reasonable assumption that the
three services are symmetric would have silently skipped this one -- the
scrape would 404 rather than fail loudly.

These tests cover the endpoint's contract (reachable, correct content type,
Prometheus text format) and that the gauges reflect real store state rather
than being emitted as static zeros.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app)


def _metric_value(body: str, name: str, labels: str = "") -> float:
    """Pull a single metric's value out of Prometheus text-format output."""
    needle = f"{name}{labels} "
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(needle):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"metric not found in output: {name}{labels}")


def test_metrics_endpoint_is_reachable(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200


def test_metrics_uses_prometheus_content_type(client):
    """A scraper keys off this content type; JSON here would be silently wrong."""
    resp = client.get("/metrics")
    assert "text/plain" in resp.headers["content-type"]
    assert "version=" in resp.headers["content-type"]


def test_metrics_exposes_verityflux_series(client):
    body = client.get("/metrics").text
    for name in (
        "verityflux_agents_registered",
        "verityflux_scans_total",
        "verityflux_api_keys_total",
        "verityflux_approvals",
    ):
        assert name in body, f"missing metric series: {name}"


def test_approvals_gauge_is_labelled_by_status(client):
    body = client.get("/metrics").text
    assert 'verityflux_approvals{status="pending"}' in body
    assert 'verityflux_approvals{status="auto_approved"}' in body


def test_gauges_track_real_state_not_constants(client):
    """
    Create an approval and confirm the gauge moves.

    Without this, every assertion above would still pass if the endpoint
    emitted hardcoded zeros -- which is exactly the class of bug (a stub that
    looks functional) this work has been closing elsewhere in the codebase.
    """
    before = _metric_value(client.get("/metrics").text, "verityflux_approvals", '{status="pending"}')

    resp = client.post(
        "/api/v1/approvals",
        headers={"Authorization": "Bearer test-token"},
        json={
            "agent_id": "metrics-test-agent",
            "agent_name": "metrics-test",
            "tool_name": "file_write",
            "action_type": "write",
            "parameters": {},
            "risk_score": 50.0,  # above auto-approve threshold -> stays pending
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    after = _metric_value(client.get("/metrics").text, "verityflux_approvals", '{status="pending"}')
    assert after == before + 1, f"pending gauge did not track the new approval ({before} -> {after})"

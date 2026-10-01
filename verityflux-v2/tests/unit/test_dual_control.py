"""Approval dual control / four-eyes (A6).

Previously any authenticated user in the org could decide any approval,
including the one who requested it -- no separation between requester and
approver. With VERITYFLUX_REQUIRE_DUAL_CONTROL enabled, the requester can no
longer self-approve; a different operator must decide. The control is opt-in
(default off) so the single-identity local/dev flow is unchanged.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

REQUESTER_KEY = "dual-control-admin-key-abc"      # -> user_id api-admin
OTHER_KEY = "dual-control-other-key-xyz"          # -> user_id api-extra-1


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _two_identities(monkeypatch):
    # Two distinct configured API keys in the same org.
    monkeypatch.setenv("VERITYFLUX_API_KEY", REQUESTER_KEY)
    monkeypatch.setenv("VERITYFLUX_EXTRA_API_KEYS", OTHER_KEY)


def _create_pending(client, key) -> str:
    r = client.post(
        "/api/v1/approvals",
        headers={"X-API-Key": key},
        json={
            "agent_id": "dc-agent", "agent_name": "dc",
            "tool_name": "file_write", "action_type": "write",
            "parameters": {}, "risk_score": 50.0,  # stays pending
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending"
    return r.json()["id"]


def test_requester_cannot_self_approve_when_enabled(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_REQUIRE_DUAL_CONTROL", "true")
    req_id = _create_pending(client, REQUESTER_KEY)
    r = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers={"X-API-Key": REQUESTER_KEY},
        json={"decision": "approve", "justification": "self"},
    )
    assert r.status_code == 403


def test_different_operator_can_approve_when_enabled(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_REQUIRE_DUAL_CONTROL", "true")
    req_id = _create_pending(client, REQUESTER_KEY)
    r = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers={"X-API-Key": OTHER_KEY},
        json={"decision": "approve", "justification": "second pair of eyes"},
    )
    assert r.status_code == 200, r.text
    rec = r.json()["record"]
    assert rec["status"] == "approved"
    assert rec["decided_by"] == "api-extra-1"
    assert rec["requested_by"] == "api-admin"


def test_self_approve_allowed_when_disabled(client, monkeypatch):
    # Default (flag unset): behaviour is unchanged -- self-approval permitted.
    monkeypatch.delenv("VERITYFLUX_REQUIRE_DUAL_CONTROL", raising=False)
    req_id = _create_pending(client, REQUESTER_KEY)
    r = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers={"X-API-Key": REQUESTER_KEY},
        json={"decision": "approve", "justification": "ok"},
    )
    assert r.status_code == 200
    assert r.json()["record"]["status"] == "approved"

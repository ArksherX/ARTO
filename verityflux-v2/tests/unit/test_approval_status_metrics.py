"""Approval decision -> canonical status, and the metrics gauge guard (F2).

Two defects:

  * A human decision stored the decision VERB as the record status
    ("approve"), but the rest of the system -- /metrics, the stats endpoint --
    reports on the canonical ApprovalStatus ("approved"). So a dashboard
    querying status="approved" saw 0 while real approvals piled into a stray
    status="approve" bucket. Decisions now map to the canonical status.

  * The Prometheus gauges register against the global default registry at
    import. A second execution of the module under a different name (script vs
    uvicorn worker import-string) raised "Duplicated timeseries" and crashed
    startup. Gauge creation is now idempotent.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from api.v2.main import _decision_to_status, _get_or_create_gauge  # noqa: E402


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app)


# --- decision -> canonical status --------------------------------------------

@pytest.mark.parametrize("decision,expected", [
    ("approve", "approved"),
    ("approve_once", "approved"),
    ("approve_always", "approved"),
    ("deny", "denied"),
    ("deny_always", "denied"),
    ("escalate", "escalated"),
    ("APPROVE", "approved"),   # case-insensitive
    ("nonsense", "pending"),   # fail safe: still needs a human
    ("", "pending"),
])
def test_decision_maps_to_canonical_status(decision, expected):
    assert _decision_to_status(decision) == expected


def test_decide_records_canonical_status_and_metric(client):
    # Create a pending approval.
    created = client.post(
        "/api/v1/approvals",
        headers={"Authorization": "Bearer test-token"},
        json={
            "agent_id": "f2-agent", "agent_name": "f2",
            "tool_name": "file_write", "action_type": "write",
            "parameters": {}, "risk_score": 50.0,  # stays pending
        },
    )
    assert created.status_code == 200
    req_id = created.json()["id"]

    # Approve it.
    decided = client.post(
        f"/api/v1/approvals/{req_id}/decide",
        headers={"Authorization": "Bearer test-token"},
        json={"decision": "approve", "justification": "ok"},
    )
    assert decided.status_code == 200
    rec = decided.json()["record"]
    assert rec["status"] == "approved"      # canonical, not the verb
    assert rec["decision"] == "approve"     # raw verb retained for audit

    # The gauge reflects it under "approved", and no stray "approve" bucket.
    body = client.get("/metrics").text
    assert 'verityflux_approvals{status="approved"}' in body
    assert 'verityflux_approvals{status="approve"}' not in body


# --- gauge creation is idempotent (crash guard) ------------------------------

def test_gauge_creation_is_idempotent():
    pytest.importorskip("prometheus_client")
    name = "verityflux_test_idempotent_gauge"
    g1 = _get_or_create_gauge(name, "first")
    g2 = _get_or_create_gauge(name, "second")  # must not raise Duplicated timeseries
    assert g1 is not None and g2 is not None

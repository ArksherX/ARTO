"""
Cross-tenant isolation tests for the VerityFlux API.

There are 31 call sites of _organization_id_from_user / _organization_id_from_record
in api/v2/main.py, but nothing previously exercised them: no test confirmed that
tenant A cannot read tenant B's records. These tests close that gap.

Driven through the real JWT path (_decode_jwt_user), not /api/v1/auth/login --
login is still a mock that returns a hardcoded organization_id of "org-123",
so it cannot express more than one tenant and is useless for isolation testing.

Includes a concurrent test: isolation that holds for sequential requests but
breaks under interleaved load is a real and common failure mode, given the
module-level dict stores these endpoints use.
"""

import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import jwt as pyjwt

TEST_JWT_SECRET = "tenant-isolation-test-secret-value"


@pytest.fixture(autouse=True)
def _jwt_env(monkeypatch):
    """Enable the real JWT auth path with a known secret."""
    monkeypatch.setenv("VERITYFLUX_JWT_SECRET", TEST_JWT_SECRET)
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app)


def _token(org_id: str, role: str = "admin") -> str:
    return pyjwt.encode(
        {"sub": f"user-{org_id}", "org_id": org_id, "role": role},
        TEST_JWT_SECRET,
        algorithm="HS256",
    )


def _headers(org_id: str) -> dict:
    return {"Authorization": f"Bearer {_token(org_id)}"}


def _create_approval(client, org_id: str, risk_score: float = 50.0) -> str:
    """Create an approval owned by org_id; return its id."""
    resp = client.post(
        "/api/v1/approvals",
        headers=_headers(org_id),
        json={
            "agent_id": f"agent-{uuid.uuid4()}",
            "agent_name": "isolation-test-agent",
            "tool_name": "file_write",
            "action_type": "write",
            "parameters": {},
            "risk_score": risk_score,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def test_jwt_carries_distinct_tenants(client):
    """Sanity check: the two tokens really do resolve to different tenants.

    Without this, every isolation assertion below could pass vacuously by
    both requests landing in the same tenant.
    """
    from api.v2.main import _decode_jwt_user

    a = _decode_jwt_user(_token("org-alpha"))
    b = _decode_jwt_user(_token("org-beta"))
    assert a is not None and b is not None
    assert a["organization_id"] == "org-alpha"
    assert b["organization_id"] == "org-beta"
    assert a["organization_id"] != b["organization_id"]


def test_approval_list_does_not_leak_across_tenants(client):
    alpha_id = _create_approval(client, "org-alpha")
    beta_id = _create_approval(client, "org-beta")
    assert alpha_id != beta_id

    alpha_view = client.get("/api/v1/approvals", headers=_headers("org-alpha"))
    assert alpha_view.status_code == 200
    alpha_ids = {row["id"] for row in alpha_view.json()["items"]}

    assert alpha_id in alpha_ids, "tenant cannot see its own record"
    assert beta_id not in alpha_ids, "LEAK: tenant alpha can see tenant beta's approval"


def test_approval_detail_blocked_across_tenants(client):
    beta_id = _create_approval(client, "org-beta")

    # Alpha attempting to read Beta's record directly by id.
    resp = client.get(f"/api/v1/approvals/{beta_id}", headers=_headers("org-alpha"))
    assert resp.status_code in (403, 404), (
        f"LEAK: cross-tenant detail read returned {resp.status_code}, "
        "expected 403 (forbidden) or 404 (not visible)"
    )


def _create_api_key(client, org_id: str) -> str:
    """Create an API key owned by org_id; return its key id."""
    resp = client.post(
        "/api/v1/auth/api-keys",
        headers=_headers(org_id),
        json={"name": f"key-{uuid.uuid4()}", "expires_in_days": 30},
    )
    assert resp.status_code == 200, resp.text
    # The response field is "key_id", not "id" (APIKeyResponse, main.py:1486).
    return resp.json()["key_id"]


def test_api_key_list_does_not_leak_across_tenants(client):
    """API keys are credentials -- a cross-tenant read here is materially
    worse than leaking a record id, so this boundary is worth its own test."""
    alpha_key = _create_api_key(client, "org-alpha")
    beta_key = _create_api_key(client, "org-beta")
    assert alpha_key != beta_key

    resp = client.get("/api/v1/auth/api-keys", headers=_headers("org-alpha"))
    assert resp.status_code == 200
    visible = {row["key_id"] for row in resp.json()}

    assert alpha_key in visible, "tenant cannot see its own API key"
    assert beta_key not in visible, "LEAK: tenant alpha can see tenant beta's API key"


def test_api_key_revoke_blocked_across_tenants(client):
    """Isolation must cover writes, not just reads: revoking another
    tenant's key would be a denial-of-service against them."""
    beta_key = _create_api_key(client, "org-beta")

    resp = client.delete(f"/api/v1/auth/api-keys/{beta_key}", headers=_headers("org-alpha"))
    assert resp.status_code in (403, 404), (
        f"LEAK: cross-tenant key revocation returned {resp.status_code}, expected 403/404"
    )

    # And confirm the key genuinely still works for its owner afterwards.
    still_there = client.get("/api/v1/auth/api-keys", headers=_headers("org-beta"))
    assert beta_key in {row["key_id"] for row in still_there.json()}, (
        "beta's key was revoked by alpha despite the request being refused"
    )


def test_scan_detail_blocked_across_tenants(client):
    """Scans carry findings about a tenant's systems."""
    create = client.post(
        "/api/v1/scans",
        headers=_headers("org-beta"),
        json={"target_type": "custom", "name": "isolation-test-scan"},
    )
    assert create.status_code == 200, create.text
    beta_scan = create.json()["scan_id"]

    resp = client.get(f"/api/v1/scans/{beta_scan}", headers=_headers("org-alpha"))
    assert resp.status_code in (403, 404), (
        f"LEAK: cross-tenant scan read returned {resp.status_code}, expected 403/404"
    )


def test_isolation_holds_under_concurrent_load(client):
    """
    Interleave two tenants' writes concurrently, then verify neither can see
    the other's records.

    Sequential isolation can pass while concurrent isolation fails -- these
    endpoints share module-level dict stores, so a race that assigns the
    wrong organization_id would only appear under interleaving.
    """
    per_tenant = 12

    def make(org_id):
        return _create_approval(client, org_id)

    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = []
        for i in range(per_tenant):
            jobs.append(("org-alpha", pool.submit(make, "org-alpha")))
            jobs.append(("org-beta", pool.submit(make, "org-beta")))
        created = {"org-alpha": set(), "org-beta": set()}
        for org_id, fut in jobs:
            created[org_id].add(fut.result())

    assert len(created["org-alpha"]) == per_tenant
    assert len(created["org-beta"]) == per_tenant
    assert not (created["org-alpha"] & created["org-beta"]), "id collision across tenants"

    for owner, other in (("org-alpha", "org-beta"), ("org-beta", "org-alpha")):
        resp = client.get("/api/v1/approvals", headers=_headers(owner), params={"limit": 200})
        assert resp.status_code == 200
        visible = {row["id"] for row in resp.json()["items"]}

        missing = created[owner] - visible
        assert not missing, f"{owner} cannot see {len(missing)} of its own records"

        leaked = created[other] & visible
        assert not leaked, (
            f"LEAK under concurrency: {owner} can see {len(leaked)} of {other}'s records"
        )

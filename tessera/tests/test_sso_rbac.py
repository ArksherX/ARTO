import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    import api_server_production as prod
except ModuleNotFoundError as exc:
    pytest.skip(f"SSO dependency missing: {exc}", allow_module_level=True)


class FakeOIDCValidator:
    def __init__(self, claims):
        self._claims = claims

    def validate_bearer(self, authorization):
        return self._claims


def _make_app(claims):
    os.environ["TESSERA_SSO_ENABLED"] = "true"
    os.environ["TESSERA_SSO_MODE"] = "oidc"
    os.environ["TESSERA_SSO_ROLE_CLAIM"] = "roles"
    os.environ["TESSERA_SSO_TENANT_CLAIM"] = "tenant_id"
    os.environ["TESSERA_SSO_ADMIN_ROLES"] = "admin,security"
    os.environ["TESSERA_SSO_ROLE_MAP"] = "{\"/tokens/revoke\": [\"security\"], \"/agents/register\": [\"admin\"]}"

    prod.OIDCValidator = lambda *a, **k: FakeOIDCValidator(claims)

    app = FastAPI()
    app.add_middleware(prod.SSOMiddleware)

    @app.post("/tokens/revoke")
    def revoke():
        return {"ok": True}

    @app.post("/agents/register")
    def register():
        return {"ok": True}

    @app.get("/metrics")
    def metrics():
        return {"ok": True}

    @app.get("/tokens/request")
    def request():
        return {"ok": True}

    return app


def test_rbac_allows_security_for_revoke():
    app = _make_app({"roles": ["security"], "tenant_id": "default"})
    client = TestClient(app)
    resp = client.post("/tokens/revoke", headers={"Authorization": "Bearer x", "X-Tenant-ID": "default"})
    assert resp.status_code == 200


def test_rbac_denies_security_for_register():
    app = _make_app({"roles": ["security"], "tenant_id": "default"})
    client = TestClient(app)
    resp = client.post("/agents/register", headers={"Authorization": "Bearer x", "X-Tenant-ID": "default"})
    assert resp.status_code == 403


def test_rbac_allows_admin_for_register():
    app = _make_app({"roles": ["admin"], "tenant_id": "default"})
    client = TestClient(app)
    resp = client.post("/agents/register", headers={"Authorization": "Bearer x", "X-Tenant-ID": "default"})
    assert resp.status_code == 200


def test_unprotected_endpoint_no_sso():
    app = _make_app({"roles": ["security"], "tenant_id": "default"})
    client = TestClient(app)
    resp = client.get("/tokens/request")
    assert resp.status_code == 200


def test_rbac_method_specific_metrics():
    app = _make_app({"roles": ["ops"]})
    client = TestClient(app)
    resp = client.get("/metrics", headers={"Authorization": "Bearer x", "X-Tenant-ID": "default"})
    assert resp.status_code == 200

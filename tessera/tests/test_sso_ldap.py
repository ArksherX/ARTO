import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    import api_server_production as prod
except ModuleNotFoundError as exc:
    pytest.skip(f"SSO dependency missing: {exc}", allow_module_level=True)


class FakeLDAP:
    def authenticate(self, username, password, search_filter=None):
        return username == "admin@example.com" and password == "secret"


def _make_app():
    os.environ["TESSERA_SSO_ENABLED"] = "true"
    os.environ["TESSERA_SSO_MODE"] = "ldap"
    os.environ["TESSERA_SSO_ADMIN_USERS"] = "admin@example.com"

    prod.LDAPAuthenticator = lambda *a, **k: FakeLDAP()

    app = FastAPI()
    app.add_middleware(prod.SSOMiddleware)

    @app.post("/tokens/revoke")
    def revoke():
        return {"ok": True}

    return app


def test_ldap_sso_allows_admin():
    app = _make_app()
    client = TestClient(app)
    import base64
    token = base64.b64encode(b"admin@example.com:secret").decode("utf-8")
    resp = client.post("/tokens/revoke", headers={"Authorization": f"Basic {token}", "X-Tenant-ID": "default"})
    assert resp.status_code == 200


def test_ldap_sso_denies_non_admin():
    app = _make_app()
    client = TestClient(app)
    import base64
    token = base64.b64encode(b"user@example.com:secret").decode("utf-8")
    resp = client.post("/tokens/revoke", headers={"Authorization": f"Basic {token}", "X-Tenant-ID": "default"})
    assert resp.status_code == 403

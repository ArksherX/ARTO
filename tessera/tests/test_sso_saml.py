import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    import api_server_production as prod
except ModuleNotFoundError as exc:
    pytest.skip(f"SSO dependency missing: {exc}", allow_module_level=True)


class FakeSAML:
    def validate_response(self, request_data):
        return {"attributes": {"roles": ["admin"]}}


def _make_app():
    os.environ["TESSERA_SSO_ENABLED"] = "true"
    os.environ["TESSERA_SSO_MODE"] = "saml"
    os.environ["SAML_SETTINGS_PATH"] = "saml_settings.example.json"

    prod.saml_from_env = lambda: FakeSAML()

    app = FastAPI()
    app.add_middleware(prod.SSOMiddleware)

    @app.post("/agents/register")
    def register():
        return {"ok": True}

    return app


def test_saml_allows_admin_role():
    app = _make_app()
    client = TestClient(app)
    resp = client.post("/agents/register", data={"SAMLResponse": "x"}, headers={"X-Tenant-ID": "default"})
    assert resp.status_code == 200

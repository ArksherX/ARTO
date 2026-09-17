"""
Tests for real JWT issuance from /api/v1/auth/login and /api/v1/auth/refresh.

Previously both endpoints returned the literal string "eyJ..." as the access
token. That string is not a JWT; it only "worked" because get_current_user()
falls back to a permissive branch granting admin to any bearer token outside
strict production mode. The practical effect was that no token carried real
identity or tenant claims, and refresh accepted absolutely anything.

These tests cover both modes:
  - No VERITYFLUX_JWT_SECRET configured -> historical placeholder behaviour
    is preserved (so existing dev/local workflows are unchanged).
  - Secret configured -> a genuine signed JWT is minted, verified, and
    refresh enforces the signature.

What is deliberately NOT asserted: that login verifies credentials. It does
not. There is no user store and the password is ignored. That remains open
work; these tests cover token issuance only, and would fail loudly if that
scope were silently widened.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import jwt as pyjwt

# >=32 bytes: below that, PyJWT emits InsecureKeyLengthWarning per RFC 7518 §3.2.
SECRET = "auth-issuance-test-secret-32-bytes-min"
ALGO = "HS256"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app)


@pytest.fixture
def signed_mode(monkeypatch):
    monkeypatch.setenv("VERITYFLUX_JWT_SECRET", SECRET)
    monkeypatch.setenv("VERITYFLUX_JWT_ALGORITHM", ALGO)
    monkeypatch.delenv("VERITYFLUX_JWT_AUDIENCE", raising=False)
    monkeypatch.delenv("VERITYFLUX_JWT_ISSUER", raising=False)
    yield


@pytest.fixture
def unsigned_mode(monkeypatch):
    monkeypatch.delenv("VERITYFLUX_JWT_SECRET", raising=False)
    yield


def _login(client):
    resp = client.post("/api/v1/auth/login", json={"email": "user@example.com", "password": "demo"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_placeholder_token_preserved_without_secret(client, unsigned_mode):
    """Without a configured secret, behaviour is unchanged from before."""
    body = _login(client)
    assert body["access_token"] == "eyJ..."
    assert body["refresh_token"] == "eyJ..."


def test_login_mints_a_real_signed_jwt(client, signed_mode):
    body = _login(client)
    token = body["access_token"]
    assert token != "eyJ...", "still returning the placeholder instead of a real token"

    claims = pyjwt.decode(token, SECRET, algorithms=[ALGO], options={"verify_aud": False})
    assert claims["sub"] == body["user_id"]
    assert claims["org_id"] == body["organization_id"]
    assert claims["role"] == body["role"]
    assert claims["token_use"] == "access"
    # Expiry and a unique id are what make the token revocable/auditable.
    assert "exp" in claims
    assert "jti" in claims


def test_access_and_refresh_tokens_are_distinguishable(client, signed_mode):
    body = _login(client)
    access = pyjwt.decode(body["access_token"], SECRET, algorithms=[ALGO], options={"verify_aud": False})
    refresh = pyjwt.decode(body["refresh_token"], SECRET, algorithms=[ALGO], options={"verify_aud": False})
    assert access["token_use"] == "access"
    assert refresh["token_use"] == "refresh"
    assert refresh["exp"] > access["exp"], "refresh token should outlive the access token"


def test_minted_token_authenticates_on_a_protected_endpoint(client, signed_mode):
    """The token must actually work, not merely decode."""
    token = _login(client)["access_token"]
    resp = client.get("/api/v1/auth/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, f"minted token rejected: {resp.status_code} {resp.text}"


def test_refresh_preserves_identity_and_tenant(client, signed_mode):
    body = _login(client)
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert resp.status_code == 200
    refreshed = resp.json()
    assert refreshed["user_id"] == body["user_id"]
    assert refreshed["organization_id"] == body["organization_id"]
    assert refreshed["role"] == body["role"]


def test_refresh_rejects_garbage_token(client, signed_mode):
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-token"})
    assert resp.status_code == 401


def test_refresh_rejects_token_signed_with_wrong_key(client, signed_mode):
    """Signature enforcement: a forged token claiming another tenant must fail.

    Before this change refresh accepted any input and always returned an
    admin token for org-123, so a forged token was indistinguishable from
    a real one.
    """
    forged = pyjwt.encode(
        {"sub": "attacker", "org_id": "org-victim", "role": "admin"},
        "attacker-controlled-key-32-bytes-minimum",
        algorithm=ALGO,
    )
    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": forged})
    assert resp.status_code == 401, "forged token was accepted"

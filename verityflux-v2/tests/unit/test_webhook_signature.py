"""Webhook signature verification (A7).

The inbound webhook endpoints are public (an external provider cannot send a
bearer token), so they must authenticate by HMAC signature. Previously they had
none -- the "# Verify signature" comments were stubs and every handler returned
200 for any body. Now:

  * when the provider's signing secret is configured, a valid signature is
    required and a bad/missing one is rejected (401);
  * when the secret is NOT configured, the endpoint stays permissive in
    dev/non-strict (so local runs and tests are unchanged) but fails closed
    (503) in strict production mode.
"""
import hashlib
import hmac
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app, raise_server_exceptions=False)


# --- signature builders (mirror each provider's real scheme) -----------------

def _slack_headers(secret: str, body: bytes, ts: str | None = None) -> dict:
    ts = ts or str(int(time.time()))
    base = b"v0:" + ts.encode() + b":" + body
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}


def _stripe_header(secret: str, body: bytes, ts: str | None = None) -> str:
    ts = ts or str(int(time.time()))
    signed = ts.encode() + b"." + body
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _pagerduty_header(secret: str, body: bytes) -> str:
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"v1={sig}"


def _hub_header(secret: str, body: bytes) -> str:
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


# =============================================================================
# Secret configured: valid signature accepted, bad/missing rejected
# =============================================================================

def test_slack_valid_signature_accepted(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    body = json.dumps({"type": "event_callback"}).encode()
    r = client.post("/api/v1/webhooks/slack/events", content=body,
                    headers=_slack_headers("slack-secret", body))
    assert r.status_code == 200


def test_slack_url_verification_challenge(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    body = json.dumps({"type": "url_verification", "challenge": "abc123"}).encode()
    r = client.post("/api/v1/webhooks/slack/events", content=body,
                    headers=_slack_headers("slack-secret", body))
    assert r.status_code == 200 and r.json().get("challenge") == "abc123"


def test_slack_bad_signature_rejected(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    body = b'{"type":"event_callback"}'
    headers = _slack_headers("WRONG-secret", body)
    r = client.post("/api/v1/webhooks/slack/events", content=body, headers=headers)
    assert r.status_code == 401


def test_slack_missing_signature_rejected(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    r = client.post("/api/v1/webhooks/slack/events", content=b'{}')
    assert r.status_code == 401


def test_slack_stale_timestamp_rejected(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    body = b'{"type":"event_callback"}'
    old = str(int(time.time()) - 3600)  # one hour old -> replay
    r = client.post("/api/v1/webhooks/slack/events", content=body,
                    headers=_slack_headers("slack-secret", body, ts=old))
    assert r.status_code == 401


def test_slack_interactive_valid(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_SLACK_SIGNING_SECRET", "slack-secret")
    body = b"payload=%7B%7D"
    r = client.post("/api/v1/webhooks/slack/interactive", content=body,
                    headers=_slack_headers("slack-secret", body))
    assert r.status_code == 200


def test_stripe_valid_and_bad(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_STRIPE_WEBHOOK_SECRET", "whsec_x")
    body = b'{"id":"evt_1"}'
    ok = client.post("/api/v1/webhooks/stripe", content=body,
                     headers={"Stripe-Signature": _stripe_header("whsec_x", body)})
    assert ok.status_code == 200
    bad = client.post("/api/v1/webhooks/stripe", content=body,
                      headers={"Stripe-Signature": _stripe_header("nope", body)})
    assert bad.status_code == 401


def test_pagerduty_valid_and_bad(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_PAGERDUTY_WEBHOOK_SECRET", "pd-secret")
    payload = {"event_type": "incident.triggered", "source": "pagerduty",
               "payload": {}}
    body = json.dumps(payload).encode()
    ok = client.post("/api/v1/webhooks/pagerduty", content=body,
                     headers={"Content-Type": "application/json",
                              "X-PagerDuty-Signature": _pagerduty_header("pd-secret", body)})
    assert ok.status_code == 200
    bad = client.post("/api/v1/webhooks/pagerduty", content=body,
                      headers={"Content-Type": "application/json",
                               "X-PagerDuty-Signature": _pagerduty_header("wrong", body)})
    assert bad.status_code == 401


def test_jira_valid_and_bad(client, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_JIRA_WEBHOOK_SECRET", "jira-secret")
    payload = {"event_type": "jira:issue_updated", "source": "jira", "payload": {}}
    body = json.dumps(payload).encode()
    ok = client.post("/api/v1/webhooks/jira", content=body,
                     headers={"Content-Type": "application/json",
                              "X-Hub-Signature": _hub_header("jira-secret", body)})
    assert ok.status_code == 200
    bad = client.post("/api/v1/webhooks/jira", content=body,
                      headers={"Content-Type": "application/json",
                               "X-Hub-Signature": _hub_header("wrong", body)})
    assert bad.status_code == 401


# =============================================================================
# No secret configured: permissive in dev (default), fail-closed in strict prod
# =============================================================================

def test_no_secret_dev_permissive(client, monkeypatch):
    for var in ("VERITYFLUX_SLACK_SIGNING_SECRET", "VERITYFLUX_STRIPE_WEBHOOK_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("MODE", raising=False)
    monkeypatch.delenv("MLRT_MODE", raising=False)
    r = client.post("/api/v1/webhooks/slack/events", content=b'{"type":"event_callback"}')
    assert r.status_code == 200  # unchanged legacy behaviour locally


def test_no_secret_strict_prod_fails_closed(client, monkeypatch):
    monkeypatch.delenv("VERITYFLUX_STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("MODE", "prod")
    monkeypatch.setenv("SUITE_STRICT_MODE", "true")
    r = client.post("/api/v1/webhooks/stripe", content=b'{"id":"evt"}')
    assert r.status_code == 503

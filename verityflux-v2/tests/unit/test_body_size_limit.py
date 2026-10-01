"""Request body-size cap enforced by bytes received, not Content-Length (E2).

The cap used to be a header-only check, so a client could omit Content-Length
(HTTP/1.1 chunked transfer) and stream a body of any size straight past it. The
limit is now enforced on the bytes actually received.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# The cap is baked in at import time; default is 1 MiB.
from api.v2.main import _MAX_BODY_BYTES  # noqa: E402

TARGET = "/api/v1/webhooks/slack/events"  # public, returns 200 on a small body in dev


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _dev_mode(monkeypatch):
    # No webhook secret + non-strict: handler would accept a small body (200),
    # so a 413 can only come from the size cap.
    monkeypatch.delenv("VERITYFLUX_SLACK_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("MODE", raising=False)
    monkeypatch.delenv("MLRT_MODE", raising=False)


def test_small_body_passes(client):
    r = client.post(TARGET, content=b'{"type":"event_callback"}')
    assert r.status_code == 200


def test_honest_oversized_content_length_rejected(client):
    big = b"a" * (_MAX_BODY_BYTES + 1024)
    r = client.post(TARGET, content=big)  # httpx sets Content-Length
    assert r.status_code == 413


def test_chunked_oversized_body_rejected(client):
    """The bypass: no Content-Length (chunked), body over the cap -> 413."""
    chunk = b"a" * (64 * 1024)
    n = (_MAX_BODY_BYTES // len(chunk)) + 4  # comfortably over the cap

    def stream():
        for _ in range(n):
            yield chunk

    # Passing an iterator makes httpx use chunked transfer (no Content-Length).
    r = client.post(TARGET, content=stream())
    assert r.status_code == 413


def test_chunked_small_body_passes(client):
    """A chunked body under the cap must still be read and handled normally."""
    def stream():
        yield b'{"type":"url_verification",'
        yield b'"challenge":"xyz"}'

    r = client.post(TARGET, content=stream())
    assert r.status_code == 200 and r.json().get("challenge") == "xyz"

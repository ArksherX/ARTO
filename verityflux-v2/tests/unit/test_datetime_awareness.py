"""
Regression tests for timezone-aware datetime handling.

Background: the codebase used naive datetime.utcnow() throughout, while the
store-reload paths (main.py's _load_*_store) parse persisted timestamps with
datetime.fromisoformat(val.replace("Z", "+00:00")), which produces *aware*
datetimes. Python refuses to subtract a naive datetime from an aware one, so
any arithmetic mixing the two raises TypeError.

That combination was a live bug, not a theoretical one: GET
/api/v1/scans/{id}/progress computes
    (now - scan["started_at"]).total_seconds()
so querying progress for any scan that had been reloaded from disk -- i.e.
any scan created before a service restart -- raised TypeError and returned
500. It went unnoticed because tests create scans in-process, where
started_at was naive and matched.

These tests pin the invariant so a future reintroduction of utcnow() fails
here rather than in production after a restart.
"""

import os
import sys
from datetime import datetime, timedelta, UTC

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from verityflux_enterprise.api.v2 import app

    return TestClient(app)


def test_reloaded_scan_progress_does_not_raise(client):
    """
    Simulate a scan restored from disk (aware started_at) and query progress.

    Before the fix this raised:
        TypeError: can't subtract offset-naive and offset-aware datetimes
    """
    from api.v2.main import SCAN_STORE

    scan_id = "datetime-awareness-regression-scan"
    SCAN_STORE[scan_id] = {
        "scan_id": scan_id,
        "organization_id": "org-123",
        "status": "running",
        # Exactly what _load_scan_store() produces for a persisted timestamp.
        "started_at": datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
        "result": None,
    }
    try:
        resp = client.get(
            f"/api/v1/scans/{scan_id}/progress",
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 200, f"progress query failed: {resp.status_code} {resp.text}"
        assert resp.json()["elapsed_seconds"] > 0
    finally:
        SCAN_STORE.pop(scan_id, None)


def test_store_reload_produces_aware_datetimes():
    """Pins the reload behaviour these tests depend on."""
    parsed = datetime.fromisoformat("2026-01-01T00:00:00Z".replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, "reload path no longer produces aware datetimes"


def test_module_timestamps_are_timezone_aware():
    """
    Any datetime the API module generates must be aware, so it can be
    compared against reloaded timestamps without TypeError.
    """
    import api.v2.main as main_module

    now = main_module.datetime.now(main_module.UTC)
    assert now.tzinfo is not None

    reloaded = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    # The operation that previously failed.
    delta = now - reloaded
    assert isinstance(delta, timedelta)


def test_no_naive_utcnow_remains_in_api_module():
    """
    Guard against reintroduction. datetime.utcnow() is both deprecated and,
    in this codebase specifically, a correctness hazard next to the aware
    datetimes the reload paths create.
    """
    from pathlib import Path

    import api.v2.main as main_module

    source = Path(main_module.__file__).read_text(encoding="utf-8")
    assert "datetime.utcnow()" not in source, (
        "datetime.utcnow() reintroduced in api/v2/main.py -- use datetime.now(UTC); "
        "mixing naive and aware datetimes raises TypeError against reloaded records"
    )

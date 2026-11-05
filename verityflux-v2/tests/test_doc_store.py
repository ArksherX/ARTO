"""
Tests for the pluggable document store behind VerityFlux's JSON stores.

API keys, approvals, scans and skill assessments lived in files on the
container filesystem: a restart lost issued keys and pending approvals, and
two instances stopped agreeing. These cover the PostgreSQL backend that
replaces that, and confirm the file backend is unchanged.

PostgreSQL tests skip unless VERITYFLUX_TEST_DSN is set.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.doc_store import (  # noqa: E402
    JsonDocStore, PostgresDocStore, build_doc_store,
)

DSN = os.getenv("VERITYFLUX_TEST_DSN", "")
needs_pg = pytest.mark.skipif(not DSN, reason="VERITYFLUX_TEST_DSN not set")


def _default(o):
    if isinstance(o, (dt.datetime, dt.date)):
        return o.isoformat()
    return str(o)


def _json(tmp_path):
    return JsonDocStore(
        global_path_fn=lambda name: tmp_path / name,
        tenant_path_fn=lambda org, name: tmp_path / "tenants" / org / name,
        iter_tenant_paths_fn=lambda name: sorted(
            (tmp_path / "tenants").glob(f"*/{name}")) if (tmp_path / "tenants").exists() else [],
        json_default=_default,
    )


def _pg():
    import psycopg2
    with psycopg2.connect(DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS verityflux_docs")
    return PostgresDocStore(DSN, json_default=_default)


@pytest.fixture(params=["json", "pg"])
def store(request, tmp_path):
    """Both backends must behave identically."""
    if request.param == "pg":
        if not DSN:
            pytest.skip("VERITYFLUX_TEST_DSN not set")
        return _pg()
    return _json(tmp_path)


def test_missing_document_reads_as_none(store):
    assert store.read(None, "api_keys.json") is None
    assert store.read("acme", "api_keys.json") is None


def test_global_round_trip(store):
    store.write(None, "api_keys.json", {"api_keys": {"k1": {"owner": "a"}}})
    assert store.read(None, "api_keys.json")["api_keys"]["k1"]["owner"] == "a"


def test_overwrite_replaces(store):
    store.write(None, "approvals.json", {"approvals": [1, 2, 3]})
    store.write(None, "approvals.json", {"approvals": [9]})
    assert store.read(None, "approvals.json")["approvals"] == [9]


def test_tenants_are_isolated(store):
    store.write("acme", "api_keys.json", {"api_keys": {"a": 1}})
    store.write("globex", "api_keys.json", {"api_keys": {"b": 2}})
    assert store.read("acme", "api_keys.json")["api_keys"] == {"a": 1}
    assert store.read("globex", "api_keys.json")["api_keys"] == {"b": 2}


def test_iter_all_returns_every_tenant_and_not_the_global_doc(store):
    store.write(None, "scans.json", {"scans": ["global"]})
    store.write("acme", "scans.json", {"scans": ["a"]})
    store.write("globex", "scans.json", {"scans": ["b"]})
    got = dict(store.iter_all("scans.json"))
    assert set(got) == {"acme", "globex"}, "iter_all must not include the shared document"
    assert got["acme"]["scans"] == ["a"]


def test_documents_with_datetimes_round_trip(store):
    """API key records carry datetimes; the default hook must handle them."""
    when = dt.datetime(2026, 11, 5, 12, 30, 0)
    store.write("acme", "api_keys.json", {"api_keys": {"k": {"created": when}}})
    got = store.read("acme", "api_keys.json")
    assert got["api_keys"]["k"]["created"].startswith("2026-11-05")


def test_names_do_not_collide(store):
    store.write("acme", "api_keys.json", {"v": "keys"})
    store.write("acme", "approvals.json", {"v": "approvals"})
    assert store.read("acme", "api_keys.json")["v"] == "keys"
    assert store.read("acme", "approvals.json")["v"] == "approvals"


@needs_pg
def test_pg_survives_a_restart():
    first = _pg()
    first.write("acme", "api_keys.json", {"api_keys": {"k1": {"owner": "a"}}})
    first.close()
    second = PostgresDocStore(DSN, json_default=_default)
    assert second.read("acme", "api_keys.json")["api_keys"]["k1"]["owner"] == "a"


# ------------------------------------------------------------ backend choice

def test_defaults_to_files(tmp_path, monkeypatch):
    monkeypatch.delenv("VERITYFLUX_DB_DSN", raising=False)
    s = build_doc_store(lambda n: tmp_path / n,
                        lambda o, n: tmp_path / o / n, lambda n: [])
    assert s.backend == "json-file"


def test_strict_mode_refuses_to_degrade_to_files(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_DB_DSN", "host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    monkeypatch.setenv("VERITYFLUX_STORE_STRICT", "true")
    with pytest.raises(RuntimeError, match="VERITYFLUX_STORE_STRICT"):
        build_doc_store(lambda n: tmp_path / n, lambda o, n: tmp_path / o / n, lambda n: [])


def test_without_strict_mode_it_still_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITYFLUX_DB_DSN", "host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    monkeypatch.delenv("VERITYFLUX_STORE_STRICT", raising=False)
    s = build_doc_store(lambda n: tmp_path / n, lambda o, n: tmp_path / o / n, lambda n: [])
    assert s.backend == "json-file"

"""
Tests for the pluggable agent-registry backends.

The registry kept agents in a JSON file on the container filesystem, so a
restart lost every registered agent and two instances diverged. These cover
the PostgreSQL backend that replaces it, and confirm the JSON backend still
behaves exactly as before so local development is unaffected.

PostgreSQL tests are skipped unless TESSERA_TEST_DSN is set:

    docker run -d --name arto-test-pg -e POSTGRES_PASSWORD=testpw \
      -e POSTGRES_USER=vestigia -e POSTGRES_DB=vestigia \
      -p 55432:5432 postgres:16-alpine
    TESSERA_TEST_DSN="host=127.0.0.1 port=55432 user=vestigia \
      password=testpw dbname=vestigia" pytest tessera/tests/test_registry_store.py
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tessera.registry_store import (  # noqa: E402
    JsonRegistryStore, PostgresRegistryStore, build_store,
)

DSN = os.getenv("TESSERA_TEST_DSN", "")
needs_pg = pytest.mark.skipif(not DSN, reason="TESSERA_TEST_DSN not set")

DEFAULTS = {"seed_agent": {"agent_id": "seed_agent", "owner": "test",
                           "tenant_id": "default", "status": "active"}}


def _json_store(tmp_path):
    return JsonRegistryStore(
        registry_path=str(tmp_path / "registry.json"),
        tenant_enabled_fn=lambda: False,
        tenant_paths_fn=lambda: [],
        tenant_path_fn=lambda t: str(tmp_path / f"{t}.json"),
        default_entries_fn=lambda: dict(DEFAULTS),
    )


def _pg_store():
    import psycopg2
    with psycopg2.connect(DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS tessera_agents")
    return PostgresRegistryStore(DSN, default_entries_fn=lambda: dict(DEFAULTS))


# --------------------------------------------------------------- JSON backend

def test_json_seeds_defaults_when_empty(tmp_path):
    store = _json_store(tmp_path)
    assert "seed_agent" in store.load()
    assert (tmp_path / "registry.json").exists()


def test_json_round_trip(tmp_path):
    store = _json_store(tmp_path)
    store.save({"a": {"agent_id": "a", "owner": "x", "tenant_id": "t1"}})
    assert store.load()["a"]["owner"] == "x"


# ----------------------------------------------------------- Postgres backend

@needs_pg
def test_pg_seeds_defaults_when_empty():
    assert "seed_agent" in _pg_store().load()


@needs_pg
def test_pg_round_trip_and_update():
    store = _pg_store()
    store.save({"a": {"agent_id": "a", "owner": "x", "tenant_id": "t1",
                      "allowed_tools": ["read"]}})
    got = store.load()
    assert got["a"]["owner"] == "x" and got["a"]["allowed_tools"] == ["read"]
    store.save({"a": {"agent_id": "a", "owner": "y", "tenant_id": "t1",
                      "allowed_tools": ["read", "write"]}})
    got = store.load()
    assert got["a"]["owner"] == "y" and len(got["a"]["allowed_tools"]) == 2


@needs_pg
def test_pg_removes_agents_that_are_gone():
    """save() replaces the set, so a deleted agent must not linger."""
    store = _pg_store()
    store.save({"a": {"agent_id": "a", "tenant_id": "default"},
                "b": {"agent_id": "b", "tenant_id": "default"}})
    assert set(store.load()) == {"a", "b"}
    store.save({"a": {"agent_id": "a", "tenant_id": "default"}})
    assert set(store.load()) == {"a"}


@needs_pg
def test_pg_survives_a_restart():
    """The point of the change: a new process sees the same agents."""
    first = _pg_store()
    first.save({f"agent{i}": {"agent_id": f"agent{i}", "tenant_id": "default"}
                for i in range(20)})
    first.close()
    second = PostgresRegistryStore(DSN, default_entries_fn=lambda: dict(DEFAULTS))
    assert len(second.load()) == 20


@needs_pg
def test_pg_save_is_atomic():
    """A failure part-way through must leave the previous set intact."""
    import psycopg2.extras
    store = _pg_store()
    store.save({"keep": {"agent_id": "keep", "tenant_id": "default"}})

    class Unserialisable:
        pass

    with pytest.raises(Exception):
        store.save({"keep": {"agent_id": "keep", "tenant_id": "default"},
                    "bad": {"agent_id": "bad", "boom": Unserialisable()}})
    assert set(store.load()) == {"keep"}, "a failed save changed the stored set"


@needs_pg
def test_pg_keeps_tenants_separate():
    store = _pg_store()
    store.save({"a": {"agent_id": "a", "tenant_id": "t1"},
                "b": {"agent_id": "b", "tenant_id": "t2"}})
    loaded = store.load()
    assert loaded["a"]["tenant_id"] == "t1"
    assert loaded["b"]["tenant_id"] == "t2"


# ------------------------------------------------------------ backend choice

def test_build_store_defaults_to_json(tmp_path, monkeypatch):
    monkeypatch.delenv("TESSERA_DB_DSN", raising=False)
    store = build_store(str(tmp_path / "r.json"), lambda: False, lambda: [],
                        lambda t: str(tmp_path / f"{t}.json"), lambda: dict(DEFAULTS))
    assert store.backend == "json-file"


@needs_pg
def test_build_store_picks_postgres_when_dsn_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv("TESSERA_DB_DSN", DSN)
    store = build_store(str(tmp_path / "r.json"), lambda: False, lambda: [],
                        lambda t: str(tmp_path / f"{t}.json"), lambda: dict(DEFAULTS))
    assert store.backend == "postgresql"


def test_strict_mode_refuses_to_degrade_to_a_file(tmp_path, monkeypatch):
    """An unreachable database must fail, not silently write to disk."""
    monkeypatch.setenv("TESSERA_DB_DSN", "host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    monkeypatch.setenv("TESSERA_REGISTRY_STRICT", "true")
    with pytest.raises(RuntimeError, match="TESSERA_REGISTRY_STRICT"):
        build_store(str(tmp_path / "r.json"), lambda: False, lambda: [],
                    lambda t: str(tmp_path / f"{t}.json"), lambda: dict(DEFAULTS))


def test_without_strict_mode_it_still_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("TESSERA_DB_DSN", "host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    monkeypatch.delenv("TESSERA_REGISTRY_STRICT", raising=False)
    store = build_store(str(tmp_path / "r.json"), lambda: False, lambda: [],
                        lambda t: str(tmp_path / f"{t}.json"), lambda: dict(DEFAULTS))
    assert store.backend == "json-file"

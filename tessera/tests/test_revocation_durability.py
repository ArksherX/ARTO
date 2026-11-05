"""
Revocation must survive a restart.

Losing a revocation is not data loss, it is a security regression: a token
that was revoked becomes valid again. The revocation set used a JSON file as
its durable layer with Redis in front as a cache. On a stateless runtime that
file disappears with the container, so the only durable layer was the one
guaranteed not to persist.

PostgreSQL is now the durable layer when TESSERA_DB_DSN is set. Redis, when
configured, stays a cache in front of it. The file remains for local use.

PostgreSQL tests skip unless TESSERA_TEST_DSN is set.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tessera.revocation import RevocationList  # noqa: E402

DSN = os.getenv("TESSERA_TEST_DSN", "")
needs_pg = pytest.mark.skipif(not DSN, reason="TESSERA_TEST_DSN not set")


def _clean_db():
    import psycopg2
    with psycopg2.connect(DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS tessera_revocations")


@pytest.fixture
def pg_env(monkeypatch, tmp_path):
    if not DSN:
        pytest.skip("TESSERA_TEST_DSN not set")
    _clean_db()
    monkeypatch.setenv("TESSERA_DB_DSN", DSN)
    monkeypatch.delenv("REDIS_URL", raising=False)      # prove it works with no Redis
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")               # unreachable on purpose
    return tmp_path


# ---------------------------------------------------------------- file backend

def test_file_backend_is_the_default(tmp_path, monkeypatch):
    monkeypatch.delenv("TESSERA_DB_DSN", raising=False)
    rl = RevocationList(revocation_file=str(tmp_path / "rev.json"))
    assert rl.backend == "json-file"
    rl.revoke("jti-1")
    assert rl.is_revoked("jti-1")


# ------------------------------------------------------------ postgres backend

@needs_pg
def test_postgres_is_used_when_a_dsn_is_set(pg_env):
    rl = RevocationList(revocation_file=str(pg_env / "rev.json"))
    assert rl.backend == "postgresql"


@needs_pg
def test_a_revoked_token_stays_revoked_across_a_restart(pg_env):
    """The whole point. Without this a restart re-enables revoked tokens."""
    first = RevocationList(revocation_file=str(pg_env / "rev.json"))
    first.revoke("jti-compromised", reason="agent breached")
    assert first.is_revoked("jti-compromised")

    second = RevocationList(revocation_file=str(pg_env / "rev.json"))   # restart
    assert second.is_revoked("jti-compromised"), \
        "a revoked token became valid again after a restart"


@needs_pg
def test_no_json_file_is_written_when_postgres_is_the_backend(pg_env):
    path = pg_env / "rev.json"
    rl = RevocationList(revocation_file=str(path))
    rl.revoke("jti-x")
    assert not path.exists(), "revocations were also written to local disk"


@needs_pg
def test_unrevoke_persists_too(pg_env):
    first = RevocationList(revocation_file=str(pg_env / "rev.json"))
    first.revoke("jti-a")
    first.revoke("jti-b")
    first.unrevoke("jti-a")

    second = RevocationList(revocation_file=str(pg_env / "rev.json"))
    assert not second.is_revoked("jti-a")
    assert second.is_revoked("jti-b")


@needs_pg
def test_two_instances_see_each_others_revocations(pg_env):
    """
    With max-instances=1 this is not yet exercised, but it is the property
    that makes raising it safe later, and it costs nothing to verify now.
    """
    a = RevocationList(revocation_file=str(pg_env / "a.json"))
    b = RevocationList(revocation_file=str(pg_env / "b.json"))
    a.revoke("jti-shared")
    # b already loaded its set, so it has to re-read to see a new revocation
    b._load_revocations()
    assert b.is_revoked("jti-shared")


@needs_pg
def test_revocation_works_with_no_redis_at_all(pg_env):
    """Deferring Memorystore must not weaken revocation."""
    rl = RevocationList(revocation_file=str(pg_env / "rev.json"))
    assert rl.redis is None, "test intends Redis to be unavailable"
    rl.revoke("jti-noredis")
    assert RevocationList(revocation_file=str(pg_env / "rev.json")).is_revoked("jti-noredis")


def test_strict_mode_refuses_to_fall_back_to_a_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TESSERA_DB_DSN", "host=127.0.0.1 port=1 dbname=nope connect_timeout=1")
    monkeypatch.setenv("TESSERA_REGISTRY_STRICT", "true")
    with pytest.raises(RuntimeError, match="revoked token valid again"):
        RevocationList(revocation_file=str(tmp_path / "rev.json"))

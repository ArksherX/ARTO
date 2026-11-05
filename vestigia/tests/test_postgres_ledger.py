"""
Tests for the PostgreSQL ledger backend.

PostgresLedger shipped with no tests and nothing importing it, while the API
logged "PostgreSQL backend configured" and /health reported postgres ok. The
ledger was still writing JSON to local disk. These tests exist so that cannot
happen again, and so the backend is safe on a runtime that restarts containers
and runs several instances at once.

Needs a PostgreSQL instance. Skipped unless VESTIGIA_TEST_DSN is set:

    docker run -d --name arto-test-pg -e POSTGRES_PASSWORD=testpw \
      -e POSTGRES_USER=vestigia -e POSTGRES_DB=vestigia \
      -p 55432:5432 postgres:16-alpine
    psql "$DSN" -f vestigia/sql/schema.sql
    psql "$DSN" -f vestigia/sql/phase7-ledger-concurrency.sql
    VESTIGIA_TEST_DSN="host=127.0.0.1 port=55432 user=vestigia \
      password=testpw dbname=vestigia" pytest vestigia/tests/test_postgres_ledger.py
"""
from __future__ import annotations

import multiprocessing as mp
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DSN = os.getenv("VESTIGIA_TEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="VESTIGIA_TEST_DSN not set")

SALT = "test-salt-do-not-use-in-production"


def _ledger():
    from core.postgres_ledger import PostgresLedger
    return PostgresLedger(dsn=DSN, secret_salt=SALT)


def _truncate():
    import psycopg2
    # TRUNCATE is not a row-level DELETE, so the append-only trigger does not
    # fire and does not need to be removed.
    with psycopg2.connect(DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("TRUNCATE vestigia_events RESTART IDENTITY CASCADE")


@pytest.fixture(autouse=True)
def clean():
    _truncate()
    yield
    _truncate()


def test_uses_postgres_not_the_json_fallback():
    """The bug this suite exists for: a DSN that silently degrades to JSON."""
    led = _ledger()
    assert led.is_postgres, "ledger fell back to JSON despite a reachable DSN"


def test_append_and_verify():
    led = _ledger()
    for i in range(10):
        led.append_event(
            actor_id=f"agent-{i}", action_type="tool_call",
            status="allowed", evidence={"summary": f"event {i}"},
        )
    ok, bad = led.verify_integrity()
    assert ok, f"chain broke at {bad}"
    assert len(led._load_ledger()) == 10


def test_chain_survives_a_restart():
    """A new process against the same database continues the same chain."""
    first = _ledger()
    for i in range(25):
        first.append_event(actor_id="a", action_type="tool_call",
                           status="allowed", evidence={"n": i})
    first.close()

    second = _ledger()            # as if the container restarted
    for i in range(25, 50):
        second.append_event(actor_id="a", action_type="tool_call",
                            status="allowed", evidence={"n": i})
    ok, bad = second.verify_integrity()
    assert ok, f"chain broke across restart at {bad}"
    rows = second._load_ledger()
    assert len(rows) == 50
    # every link joins to its predecessor
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["integrity_hash"]


def _worker(args):
    """Separate process, own pool: this is what two Cloud Run instances do."""
    dsn, salt, n, tag = args
    os.environ["VESTIGIA_SECRET_SALT"] = salt
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.postgres_ledger import PostgresLedger
    led = PostgresLedger(dsn=dsn, secret_salt=salt)
    written = 0
    errors = []
    for i in range(n):
        try:
            led.append_event(actor_id=f"w{tag}", action_type="tool_call",
                             status="allowed", evidence={"w": tag, "i": i})
            written += 1
        except Exception as exc:          # a fork must not pass silently
            errors.append(str(exc))
    led.close()
    return written, errors


def test_concurrent_appends_produce_one_unbroken_chain():
    """
    The test that decides whether this can run on Cloud Run at all.

    Four processes append at once. The chain afterwards must be a single
    unbroken line containing every write. A fork would leave two chains that
    each verify internally while the ledger as a whole is wrong.
    """
    procs, per = 4, 15
    with mp.Pool(procs) as pool:
        results = pool.map(_worker, [(DSN, SALT, per, t) for t in range(procs)])

    written = sum(r[0] for r in results)
    errors = [e for r in results for e in r[1]]
    assert not errors, f"appends failed under concurrency: {errors[:3]}"
    assert written == procs * per

    led = _ledger()
    ok, bad = led.verify_integrity()
    assert ok, f"concurrent appends forked the chain at sequence {bad}"

    rows = led._load_ledger()
    assert len(rows) == procs * per, f"lost writes: {len(rows)} of {procs*per}"
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["integrity_hash"], "chain is not linear"
    # exactly one genesis
    assert sum(1 for r in rows if r["previous_hash"] == "GENESIS") == 1


def test_a_fork_cannot_be_committed_even_bypassing_the_lock():
    """
    The UNIQUE constraint is the second guard. Insert a row chaining off a
    parent that already has a successor, going around append_event entirely.
    """
    import psycopg2
    led = _ledger()
    for i in range(3):
        led.append_event(actor_id="a", action_type="tool_call",
                         status="allowed", evidence={"i": i})
    rows = led._load_ledger()
    already_used_parent = rows[1]["previous_hash"]

    with pytest.raises(psycopg2.errors.UniqueViolation):
        with psycopg2.connect(DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vestigia_events
                      (event_id, timestamp, tenant_id, actor_id, action_type,
                       status, evidence, integrity_hash, previous_hash)
                    VALUES (%s, now(), NULL, 'forker', 'tool_call', 'allowed',
                            '{}'::jsonb, %s, %s)
                    """,
                    (str(uuid.uuid4()), "deadbeef" * 8, already_used_parent),
                )


def test_ledger_is_append_only():
    """UPDATE and DELETE must be refused by the database, not by convention."""
    import psycopg2
    led = _ledger()
    led.append_event(actor_id="a", action_type="tool_call",
                     status="allowed", evidence={"x": 1})
    for sql in ("UPDATE vestigia_events SET actor_id='tampered'",
                "DELETE FROM vestigia_events"):
        with pytest.raises(psycopg2.Error, match="append-only"):
            with psycopg2.connect(DSN) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)


def test_strict_mode_refuses_to_degrade_to_json(monkeypatch):
    """
    With VESTIGIA_LEDGER_STRICT set, an unreachable database must raise rather
    than quietly writing evidence to the container filesystem.
    """
    from core.postgres_ledger import PostgresLedger
    monkeypatch.setenv("VESTIGIA_LEDGER_STRICT", "true")
    with pytest.raises(RuntimeError, match="VESTIGIA_LEDGER_STRICT"):
        PostgresLedger(dsn="host=127.0.0.1 port=1 dbname=nope connect_timeout=1")


def test_without_strict_mode_it_still_falls_back(monkeypatch, tmp_path):
    """The fallback stays available for local development."""
    from core.postgres_ledger import PostgresLedger
    monkeypatch.delenv("VESTIGIA_LEDGER_STRICT", raising=False)
    led = PostgresLedger(
        dsn="host=127.0.0.1 port=1 dbname=nope connect_timeout=1",
        fallback_ledger_path=str(tmp_path / "ledger.json"),
    )
    assert not led.is_postgres

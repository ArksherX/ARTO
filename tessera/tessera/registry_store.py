"""
Pluggable persistence for the agent registry.

The registry held agents in a JSON file. That is fine on one machine and wrong
on a stateless runtime: the file lives on a container filesystem, so a restart
loses every registered agent and two instances diverge silently.

This splits *where* agents are stored from *what* the registry does with them.
All identity, key management and signing logic in TesseraRegistry is unchanged;
only load and save move.

Backend is chosen by TESSERA_DB_DSN. Without it the JSON store is used, so
local development and the existing tests behave exactly as before.

As with the Vestigia ledger, a DSN that cannot be reached must not quietly
degrade to a file: set TESSERA_REGISTRY_STRICT=true in any deployed
environment and an unreachable database becomes a startup failure instead of
silent data loss.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tessera.registry_store")

Entry = Dict[str, Any]
Entries = Dict[str, Entry]


class JsonRegistryStore:
    """Agents in a JSON file, or one file per tenant. The original behaviour."""

    def __init__(self, registry_path: str, tenant_enabled_fn, tenant_paths_fn,
                 tenant_path_fn, default_entries_fn):
        self.registry_path = registry_path
        self._tenant_enabled = tenant_enabled_fn
        self._tenant_paths = tenant_paths_fn
        self._tenant_path = tenant_path_fn
        self._default_entries = default_entries_fn

    @property
    def backend(self) -> str:
        return "json-file"

    def load(self) -> Entries:
        out: Entries = {}
        tenant_paths = self._tenant_paths() if self._tenant_enabled() else []
        if tenant_paths:
            for path in tenant_paths:
                with open(path, "r") as fh:
                    out.update(json.load(fh))
            return out
        if self._tenant_enabled():
            return out
        if not os.path.exists(self.registry_path):
            defaults = self._default_entries()
            os.makedirs(os.path.dirname(self.registry_path) or ".", exist_ok=True)
            with open(self.registry_path, "w") as fh:
                json.dump(defaults, fh, indent=4)
            return dict(defaults)
        with open(self.registry_path, "r") as fh:
            return json.load(fh)

    def save(self, entries: Entries) -> None:
        if self._tenant_enabled():
            grouped: Dict[str, Entries] = {}
            for agent_id, entry in entries.items():
                grouped.setdefault(entry.get("tenant_id") or "default", {})[agent_id] = entry
            for tenant_id, data in grouped.items():
                path = Path(self._tenant_path(tenant_id))
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "w") as fh:
                    json.dump(data, fh, indent=4)
            return
        os.makedirs(os.path.dirname(self.registry_path) or ".", exist_ok=True)
        with open(self.registry_path, "w") as fh:
            json.dump(entries, fh, indent=4)


class PostgresRegistryStore:
    """
    Agents in PostgreSQL, one row each, the entry kept as JSONB.

    JSONB rather than a column per field on purpose: AgentIdentity still owns
    the shape, so adding a field needs no migration. The columns that exist are
    the ones queried or constrained.
    """

    DDL = """
    CREATE TABLE IF NOT EXISTS tessera_agents (
        agent_id    VARCHAR(255) PRIMARY KEY,
        tenant_id   VARCHAR(255) NOT NULL DEFAULT 'default',
        entry       JSONB        NOT NULL,
        updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_tessera_agents_tenant
        ON tessera_agents (tenant_id);
    """

    def __init__(self, dsn: str, default_entries_fn, pool_min: int = 1, pool_max: int = 10):
        self.dsn = dsn
        self._default_entries = default_entries_fn
        self._pool = None
        import psycopg2
        import psycopg2.pool
        self._pool = psycopg2.pool.SimpleConnectionPool(pool_min, pool_max, dsn)
        conn = self._pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(self.DDL)
        finally:
            self._pool.putconn(conn)
        logger.info("Tessera registry backend: PostgreSQL")

    @property
    def backend(self) -> str:
        return "postgresql"

    def _conn(self):
        return self._pool.getconn()

    def _put(self, conn):
        self._pool.putconn(conn)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
            self._pool = None

    def load(self) -> Entries:
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_id, entry FROM tessera_agents")
                rows = cur.fetchall()
        finally:
            self._put(conn)
        if rows:
            return {agent_id: entry for agent_id, entry in rows}
        # empty database: seed the same defaults the JSON store would create
        defaults = self._default_entries()
        if defaults:
            self.save(defaults)
        return dict(defaults)

    def save(self, entries: Entries) -> None:
        """
        Replace the stored set with `entries`, in one transaction.

        Upsert what is present and delete what is not, so a removed agent does
        not linger. The whole thing commits or none of it does.
        """
        import psycopg2.extras
        conn = self._conn()
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                for agent_id, entry in entries.items():
                    cur.execute(
                        """
                        INSERT INTO tessera_agents (agent_id, tenant_id, entry, updated_at)
                        VALUES (%s, %s, %s, now())
                        ON CONFLICT (agent_id) DO UPDATE
                          SET tenant_id  = EXCLUDED.tenant_id,
                              entry      = EXCLUDED.entry,
                              updated_at = now()
                        """,
                        (agent_id, entry.get("tenant_id") or "default",
                         psycopg2.extras.Json(entry)),
                    )
                if entries:
                    cur.execute(
                        "DELETE FROM tessera_agents WHERE NOT (agent_id = ANY(%s))",
                        (list(entries.keys()),),
                    )
                else:
                    cur.execute("DELETE FROM tessera_agents")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.autocommit = True
            self._put(conn)


def build_store(registry_path: str, tenant_enabled_fn, tenant_paths_fn,
                tenant_path_fn, default_entries_fn):
    """Pick the backend from the environment. JSON unless a DSN is set."""
    dsn = os.getenv("TESSERA_DB_DSN", "").strip()
    strict = os.getenv("TESSERA_REGISTRY_STRICT", "false").lower() == "true"
    if dsn:
        try:
            return PostgresRegistryStore(dsn, default_entries_fn)
        except Exception as exc:
            if strict:
                raise RuntimeError(
                    f"Tessera registry requires PostgreSQL but it is unavailable: {exc}. "
                    "Refusing to fall back to a JSON file because "
                    "TESSERA_REGISTRY_STRICT=true."
                ) from exc
            logger.warning(
                "PostgreSQL unavailable (%s) -- registry falling back to JSON: %s",
                dsn, exc,
            )
    return JsonRegistryStore(registry_path, tenant_enabled_fn, tenant_paths_fn,
                             tenant_path_fn, default_entries_fn)

"""
Pluggable persistence for VerityFlux's JSON document stores.

API keys, approvals, scan results and skill assessments were JSON files under
data/, optionally sharded one directory per tenant. That works on one machine
and fails on a stateless runtime: the files sit on a container filesystem, so
a restart loses issued API keys and pending approvals, and two instances stop
agreeing about either.

Every one of those stores is the same shape -- a JSON document addressed by
(organization, name) -- so one small store serves all of them.

Backend comes from VERITYFLUX_DB_DSN. Without it the file store is used and
behaviour is exactly as before, so local development and the existing tests
are unaffected. In a deployed environment set VERITYFLUX_STORE_STRICT=true so
an unreachable database fails at startup instead of silently writing to a disk
that is about to disappear.

`organization` is None for the single shared document, or a tenant id for the
sharded case. The database keeps those apart with a '' sentinel so the primary
key stays simple.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("verityflux.doc_store")

Doc = Dict[str, Any]
_GLOBAL = ""          # sentinel for "not tenant scoped"


class JsonDocStore:
    """Documents as JSON files. The original behaviour."""

    def __init__(self, global_path_fn: Callable[[str], Path],
                 tenant_path_fn: Callable[[str, str], Path],
                 iter_tenant_paths_fn: Callable[[str], List[Path]],
                 json_default=None):
        self._global_path = global_path_fn
        self._tenant_path = tenant_path_fn
        self._iter_tenant = iter_tenant_paths_fn
        self._json_default = json_default

    @property
    def backend(self) -> str:
        return "json-file"

    def read(self, organization: Optional[str], name: str) -> Optional[Doc]:
        path = self._tenant_path(organization, name) if organization else self._global_path(name)
        if not Path(path).exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Failed to read %s: %s", path, exc)
            return None

    def write(self, organization: Optional[str], name: str, doc: Doc) -> None:
        path = Path(self._tenant_path(organization, name) if organization
                    else self._global_path(name))
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=self._json_default)

    def iter_all(self, name: str) -> List[Tuple[str, Doc]]:
        out: List[Tuple[str, Doc]] = []
        for path in self._iter_tenant(name):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    out.append((Path(path).parent.name, json.load(fh)))
            except Exception as exc:
                logger.warning("Failed to read tenant store %s: %s", path, exc)
        return out


class PostgresDocStore:
    """
    Documents in PostgreSQL, one row per (organization, name), body as JSONB.

    The shape of each document still belongs to the caller, so no migration is
    needed when a field is added.
    """

    DDL = """
    CREATE TABLE IF NOT EXISTS verityflux_docs (
        organization VARCHAR(255) NOT NULL DEFAULT '',
        name         VARCHAR(255) NOT NULL,
        doc          JSONB        NOT NULL,
        updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
        PRIMARY KEY (organization, name)
    );
    CREATE INDEX IF NOT EXISTS idx_verityflux_docs_name
        ON verityflux_docs (name);
    """

    def __init__(self, dsn: str, json_default=None, pool_min: int = 1, pool_max: int = 10):
        self.dsn = dsn
        self._json_default = json_default
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
        logger.info("VerityFlux document store backend: PostgreSQL")

    @property
    def backend(self) -> str:
        return "postgresql"

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
            self._pool = None

    def read(self, organization: Optional[str], name: str) -> Optional[Doc]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT doc FROM verityflux_docs WHERE organization=%s AND name=%s",
                    (organization or _GLOBAL, name),
                )
                row = cur.fetchone()
                return row[0] if row else None
        finally:
            self._pool.putconn(conn)

    def write(self, organization: Optional[str], name: str, doc: Doc) -> None:
        import psycopg2.extras
        # Round-trip through json.dumps so the caller's default= hook applies
        # to values psycopg2 would otherwise refuse, such as datetimes.
        payload = json.loads(json.dumps(doc, default=self._json_default))
        conn = self._pool.getconn()
        try:
            conn.autocommit = False
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO verityflux_docs (organization, name, doc, updated_at)
                    VALUES (%s, %s, %s, now())
                    ON CONFLICT (organization, name) DO UPDATE
                      SET doc = EXCLUDED.doc, updated_at = now()
                    """,
                    (organization or _GLOBAL, name, psycopg2.extras.Json(payload)),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.autocommit = True
            self._pool.putconn(conn)

    def iter_all(self, name: str) -> List[Tuple[str, Doc]]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT organization, doc FROM verityflux_docs "
                    "WHERE name=%s AND organization <> %s ORDER BY organization",
                    (name, _GLOBAL),
                )
                return [(org, doc) for org, doc in cur.fetchall()]
        finally:
            self._pool.putconn(conn)


def build_doc_store(global_path_fn, tenant_path_fn, iter_tenant_paths_fn,
                    json_default=None):
    """Pick the backend from the environment. Files unless a DSN is set."""
    dsn = os.getenv("VERITYFLUX_DB_DSN", "").strip()
    strict = os.getenv("VERITYFLUX_STORE_STRICT", "false").lower() == "true"
    if dsn:
        try:
            return PostgresDocStore(dsn, json_default=json_default)
        except Exception as exc:
            if strict:
                raise RuntimeError(
                    f"VerityFlux requires PostgreSQL but it is unavailable: {exc}. "
                    "Refusing to fall back to local files because "
                    "VERITYFLUX_STORE_STRICT=true."
                ) from exc
            logger.warning(
                "PostgreSQL unavailable (%s) -- document store falling back to files: %s",
                dsn, exc,
            )
    return JsonDocStore(global_path_fn, tenant_path_fn, iter_tenant_paths_fn,
                        json_default=json_default)

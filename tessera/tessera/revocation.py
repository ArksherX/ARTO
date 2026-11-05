"""
Tessera Revocation List - Token Blacklisting (Redis-backed with file fallback)
"""
from typing import Set, Optional
import json
import logging
import os
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("tessera.revocation")

try:
    import redis
except Exception:  # pragma: no cover - optional dependency at runtime
    redis = None

class _PostgresRevocationStore:
    """
    Durable revocation set in PostgreSQL.

    Revocation is the one piece of state where losing it is not data loss but
    a security regression: a forgotten revocation makes a revoked token valid
    again. A file on a container filesystem cannot be the durable layer, and
    Redis is a cache with an expiry, so neither is sufficient on its own.
    """

    DDL = """
    CREATE TABLE IF NOT EXISTS tessera_revocations (
        jti        VARCHAR(255) PRIMARY KEY,
        reason     TEXT,
        revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """

    def __init__(self, dsn: str):
        import psycopg2
        import psycopg2.pool
        self._pool = psycopg2.pool.SimpleConnectionPool(1, 5, dsn)
        conn = self._pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(self.DDL)
        finally:
            self._pool.putconn(conn)

    @property
    def backend(self) -> str:
        return "postgresql"

    def load(self) -> Set[str]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT jti FROM tessera_revocations")
                return {row[0] for row in cur.fetchall()}
        finally:
            self._pool.putconn(conn)

    def add(self, jti: str, reason: Optional[str] = None) -> None:
        conn = self._pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tessera_revocations (jti, reason) VALUES (%s, %s) "
                    "ON CONFLICT (jti) DO NOTHING",
                    (jti, reason),
                )
        finally:
            self._pool.putconn(conn)

    def remove(self, jti: str) -> None:
        conn = self._pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DELETE FROM tessera_revocations WHERE jti = %s", (jti,))
        finally:
            self._pool.putconn(conn)


class RevocationList:
    """Manages revoked tokens (JWT IDs)"""
    
    def __init__(self, revocation_file: str = "data/revoked_tokens.json"):
        self.revocation_file = Path(revocation_file)
        self.revocation_file.parent.mkdir(exist_ok=True)
        self.revoked_tokens: Set[str] = set()
        self.redis = None
        self.durable = None
        self._init_durable()
        self._init_redis()
        self._load_revocations()

    def _init_durable(self):
        """
        PostgreSQL replaces the file as the durable layer when a DSN is set.

        Order of responsibilities, which matters: PostgreSQL is where a
        revocation survives, Redis is a fast shared cache in front of it, and
        the file is for local development only. With no Redis configured this
        still works correctly -- it is simply a database round trip rather
        than a cache hit, which is why deferring Memorystore is safe.
        """
        dsn = os.getenv("TESSERA_DB_DSN", "").strip()
        if not dsn:
            return
        try:
            self.durable = _PostgresRevocationStore(dsn)
        except Exception as exc:
            if os.getenv("TESSERA_REGISTRY_STRICT", "false").lower() == "true":
                raise RuntimeError(
                    f"Tessera revocations require PostgreSQL but it is unavailable: {exc}. "
                    "Refusing to fall back to a file, because a lost revocation makes a "
                    "revoked token valid again."
                ) from exc
            logger.warning(
                "PostgreSQL unavailable for revocations -- falling back to %s: %s",
                self.revocation_file, exc,
            )

    @property
    def backend(self) -> str:
        return "postgresql" if self.durable else "json-file"

    def _init_redis(self):
        """Initialize Redis client if available/configured."""
        if redis is None:
            return
        redis_url = os.getenv("REDIS_URL")
        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", "6379"))
        db = int(os.getenv("REDIS_DB", "0"))
        try:
            if redis_url:
                self.redis = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
            else:
                self.redis = redis.Redis(host=host, port=port, db=db, decode_responses=True, socket_connect_timeout=2)
            self.redis.ping()
        except Exception:
            self.redis = None
    
    def _load_revocations(self):
        """Load revoked tokens from the durable layer."""
        if self.durable:
            self.revoked_tokens = self.durable.load()
            return
        if self.revocation_file.exists():
            with open(self.revocation_file, 'r') as f:
                data = json.load(f)
                self.revoked_tokens = set(data.get('revoked', []))
    
    def _save_revocations(self):
        """Persist the whole set. Only the file backend needs a full rewrite."""
        if self.durable:
            return
        with open(self.revocation_file, 'w') as f:
            json.dump({'revoked': list(self.revoked_tokens)}, f)
    
    def revoke(self, jti: str, ttl: Optional[int] = None, reason: Optional[str] = None):
        """Revoke a token by its JWT ID"""
        self.revoked_tokens.add(jti)
        if self.durable:
            self.durable.add(jti, reason)
        else:
            self._save_revocations()
        if self.redis:
            try:
                key = f"tessera:revoked:{jti}"
                payload = json.dumps({
                    "revoked_at": datetime.utcnow().isoformat(),
                    "reason": reason
                })
                # Revocation must outlive the token; the file set is the durable
                # source of truth and Redis is only a fast cache. Default long.
                ttl_seconds = int(ttl) if ttl else 7 * 24 * 3600
                self.redis.setex(key, ttl_seconds, payload)
            except Exception:
                pass

    def add(self, jti: str, reason: Optional[str] = None, ttl: Optional[int] = None):
        """Compatibility alias for revoke()."""
        self.revoke(jti, ttl=ttl, reason=reason)
    
    def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked.

        The durable file-backed set is authoritative: once revoked, a token
        stays revoked regardless of Redis cache expiry. Redis is consulted only
        as a fast path for tokens not already in the local set.
        """
        if jti in self.revoked_tokens:
            return True
        if self.redis:
            try:
                return self.redis.exists(f"tessera:revoked:{jti}") > 0
            except Exception:
                pass
        return False
    
    def unrevoke(self, jti: str):
        """Remove a token from revocation list (file set and Redis cache)."""
        if jti in self.revoked_tokens:
            self.revoked_tokens.remove(jti)
            if self.durable:
                self.durable.remove(jti)
            else:
                self._save_revocations()
        if self.redis:
            try:
                self.redis.delete(f"tessera:revoked:{jti}")
            except Exception:
                pass

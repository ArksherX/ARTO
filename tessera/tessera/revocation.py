"""
Tessera Revocation List - Token Blacklisting (Redis-backed with file fallback)
"""
from typing import Set, Optional
import json
import os
from pathlib import Path
from datetime import datetime

try:
    import redis
except Exception:  # pragma: no cover - optional dependency at runtime
    redis = None

class RevocationList:
    """Manages revoked tokens (JWT IDs)"""
    
    def __init__(self, revocation_file: str = "data/revoked_tokens.json"):
        self.revocation_file = Path(revocation_file)
        self.revocation_file.parent.mkdir(exist_ok=True)
        self.revoked_tokens: Set[str] = set()
        self.redis = None
        self._init_redis()
        self._load_revocations()

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
        """Load revoked tokens from file"""
        if self.revocation_file.exists():
            with open(self.revocation_file, 'r') as f:
                data = json.load(f)
                self.revoked_tokens = set(data.get('revoked', []))
    
    def _save_revocations(self):
        """Persist revocations to file"""
        with open(self.revocation_file, 'w') as f:
            json.dump({'revoked': list(self.revoked_tokens)}, f)
    
    def revoke(self, jti: str, ttl: Optional[int] = None, reason: Optional[str] = None):
        """Revoke a token by its JWT ID"""
        self.revoked_tokens.add(jti)
        self._save_revocations()
        if self.redis:
            try:
                key = f"tessera:revoked:{jti}"
                payload = json.dumps({
                    "revoked_at": datetime.utcnow().isoformat(),
                    "reason": reason
                })
                ttl_seconds = int(ttl) if ttl else 3600
                self.redis.setex(key, ttl_seconds, payload)
            except Exception:
                pass

    def add(self, jti: str, reason: Optional[str] = None, ttl: Optional[int] = None):
        """Compatibility alias for revoke()."""
        self.revoke(jti, ttl=ttl, reason=reason)
    
    def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked"""
        if self.redis:
            try:
                return self.redis.exists(f"tessera:revoked:{jti}") > 0
            except Exception:
                pass
        return jti in self.revoked_tokens
    
    def unrevoke(self, jti: str):
        """Remove a token from revocation list"""
        if jti in self.revoked_tokens:
            self.revoked_tokens.remove(jti)
            self._save_revocations()

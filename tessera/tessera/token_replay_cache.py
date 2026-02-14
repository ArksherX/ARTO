#!/usr/bin/env python3
"""
JWT Replay Cache
Prevents reuse of one-time tokens that include a nonce.
"""

from __future__ import annotations

import os
import time
from typing import Dict

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class TokenReplayCache:
    """Redis-backed replay cache with in-memory fallback."""

    def __init__(self):
        self._in_memory: Dict[str, float] = {}
        self.redis = None
        self._init_redis()

    def _init_redis(self):
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

    def _cleanup(self):
        now = time.time()
        expired = [k for k, v in self._in_memory.items() if v <= now]
        for key in expired:
            del self._in_memory[key]

    def check_and_store(self, nonce: str, ttl_seconds: int) -> bool:
        """
        Returns True if nonce is new and stored, False if replay detected.
        """
        if not nonce:
            return False
        if self.redis:
            try:
                key = f"tessera:nonce:{nonce}"
                if self.redis.set(key, "1", nx=True, ex=ttl_seconds):
                    return True
                return False
            except Exception:
                pass

        self._cleanup()
        now = time.time()
        if nonce in self._in_memory and self._in_memory[nonce] > now:
            return False
        self._in_memory[nonce] = now + ttl_seconds
        return True

#!/usr/bin/env python3
"""
Rate Limiter (fixed window) with Redis-backed counter.
"""

from __future__ import annotations

import os
import time
from typing import Dict

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class RateLimiter:
    """Fixed-window rate limiter with Redis fallback."""

    def __init__(self):
        self.redis = None
        self._in_memory: Dict[str, int] = {}
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

    def allow(self, key: str, limit: int = 100, window_seconds: int = 3600) -> bool:
        if not key:
            return False
        window = int(time.time() / window_seconds)
        bucket = f"tessera:ratelimit:{key}:{window}"
        if self.redis:
            try:
                value = self.redis.incr(bucket)
                if value == 1:
                    self.redis.expire(bucket, window_seconds)
                return value <= limit
            except Exception:
                pass

        # In-memory fallback
        count = self._in_memory.get(bucket, 0) + 1
        self._in_memory[bucket] = count
        return count <= limit

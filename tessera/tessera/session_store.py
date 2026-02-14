#!/usr/bin/env python3
"""
Session State Store
Redis-backed session memory hash storage with in-memory fallback.
"""

from __future__ import annotations

import os
import json
import hashlib
from typing import Optional

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class SessionStateStore:
    """Persist and retrieve session memory hashes for agents."""

    def __init__(self):
        self._in_memory = {}
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

    @staticmethod
    def compute_memory_hash(memory_state: bytes) -> str:
        return hashlib.sha256(memory_state).hexdigest()

    def set_memory_hash(self, agent_id: str, session_id: str, memory_hash: str, ttl: int = 3600):
        key = f"tessera:session:{agent_id}:{session_id}"
        payload = json.dumps({"memory_hash": memory_hash})
        if self.redis:
            try:
                self.redis.setex(key, ttl, payload)
                return
            except Exception:
                pass
        self._in_memory[key] = payload

    def get_memory_hash(self, agent_id: str, session_id: str) -> Optional[str]:
        key = f"tessera:session:{agent_id}:{session_id}"
        if self.redis:
            try:
                data = self.redis.get(key)
                if data:
                    return json.loads(data).get("memory_hash")
            except Exception:
                pass
        data = self._in_memory.get(key)
        if data:
            return json.loads(data).get("memory_hash")
        return None

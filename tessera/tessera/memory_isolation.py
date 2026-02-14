#!/usr/bin/env python3
"""
Session-scoped memory isolation with hashing and integrity verification.
"""

from __future__ import annotations

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class MemoryIsolationManager:
    """Manages session-scoped memory with tamper detection."""

    def __init__(self):
        self.redis = None
        self._in_memory: Dict[str, Dict[str, Any]] = {}
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

    def _session_key(self, session_id: str) -> str:
        return f"tessera:memory:{session_id}"

    @staticmethod
    def _compute_hash(memories: Dict[str, Any]) -> str:
        payload = json.dumps(memories, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_session(self, agent_id: str, ttl_seconds: int = 86400) -> str:
        session_id = f"mem_{agent_id}_{datetime.utcnow().timestamp()}"
        record = {"agent_id": agent_id, "memories": {}, "memory_hash": self._compute_hash({})}
        if self.redis:
            self.redis.setex(self._session_key(session_id), ttl_seconds, json.dumps(record))
        else:
            self._in_memory[session_id] = record
        return session_id

    def store_memory(self, session_id: str, key: str, value: Any, ttl_seconds: int = 86400):
        record = self._get_record(session_id)
        if record is None:
            raise ValueError("Session not found")
        record["memories"][key] = value
        record["memory_hash"] = self._compute_hash(record["memories"])
        self._save_record(session_id, record, ttl_seconds)

    def get_memory(self, session_id: str, key: str) -> Optional[Any]:
        record = self._get_record(session_id)
        if record is None:
            return None
        return record["memories"].get(key)

    def verify_integrity(self, session_id: str) -> bool:
        record = self._get_record(session_id)
        if record is None:
            return False
        expected = self._compute_hash(record["memories"])
        return expected == record.get("memory_hash")

    def snapshot(self, session_id: str) -> Dict[str, Any]:
        record = self._get_record(session_id)
        if record is None:
            raise ValueError("Session not found")
        return {"memories": dict(record["memories"]), "memory_hash": record["memory_hash"]}

    def _get_record(self, session_id: str) -> Optional[Dict[str, Any]]:
        if self.redis:
            data = self.redis.get(self._session_key(session_id))
            return json.loads(data) if data else None
        return self._in_memory.get(session_id)

    def _save_record(self, session_id: str, record: Dict[str, Any], ttl_seconds: int):
        if self.redis:
            self.redis.setex(self._session_key(session_id), ttl_seconds, json.dumps(record))
        else:
            self._in_memory[session_id] = record

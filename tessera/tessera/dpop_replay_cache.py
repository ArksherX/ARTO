#!/usr/bin/env python3
"""
DPoP Replay Cache
Prevents reuse of DPoP proof jti values.

Rejection is classified, not just returned. A repeated jti can mean two very
different things:

  REPLAY        the same proof presented again for the same request — often a
                client retry or a naive capture-and-resend
  SUBSTITUTION  the same proof presented for a *different* request — a captured
                credential being reused to authorise something it was never
                issued for

Both are refused, but they warrant different responses: the first is frequently
benign, the second never is. Storing a sentinel value collapses them into one
indistinguishable failure, so the stored value is a binding hash over what the
proof was issued for. On a collision the stored binding is compared with the
presented one, which separates the two cases.

Pattern adopted from CAGE's ConsequenceAuthorityStore
(src/gateway/governance/consequence_authority_store.py), which makes the same
distinction for single-use consequence tokens.
"""

from __future__ import annotations

import hashlib
import os
import time
from enum import Enum
from typing import Dict, Optional, Tuple

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


class ReplayOutcome(str, Enum):
    """Result of presenting a jti to the cache."""

    ACCEPTED = "accepted"
    #: Same jti, same binding — the identical request presented twice.
    REPLAY = "replay"
    #: Same jti, different binding — the proof is being reused for another
    #: request. Always an attack; never a retry.
    SUBSTITUTION = "substitution"
    #: Rejected without a binding available to compare against, so the two
    #: cases above could not be separated.
    REPLAY_UNCLASSIFIED = "replay_unclassified"


#: Stored when a caller supplies no binding, preserving the historical value.
_NO_BINDING = "1"


class DPoPReplayCache:
    """Redis-backed replay cache with in-memory fallback."""

    def __init__(self):
        self._in_memory: Dict[str, float] = {}
        self._in_memory_bindings: Dict[str, str] = {}
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
    def binding_hash(**parts: Optional[str]) -> str:
        """Hash the fields describing what a proof was issued for.

        Pass whatever is available at the call site — typically the HTTP method
        and URI the proof is bound to, plus the agent and the action digest.
        Field names are included so that reordering or renaming cannot produce
        a collision, and None values are skipped so callers need not supply
        every field.
        """
        material = ":".join(
            f"{k}={v}" for k, v in sorted(parts.items()) if v is not None
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _cleanup(self):
        now = time.time()
        expired = [k for k, v in self._in_memory.items() if v <= now]
        for key in expired:
            del self._in_memory[key]
            self._in_memory_bindings.pop(key, None)

    def check_and_classify(
        self,
        jti: str,
        ttl_seconds: int = 60,
        binding: Optional[str] = None,
    ) -> Tuple[bool, ReplayOutcome]:
        """Store the jti if unseen; otherwise classify why it was refused.

        Returns (accepted, outcome). `accepted` carries the same meaning as
        check_and_store()'s return value.
        """
        if not jti:
            return False, ReplayOutcome.REPLAY_UNCLASSIFIED

        value = binding if binding is not None else _NO_BINDING

        if self.redis:
            try:
                key = f"tessera:dpop:jti:{jti}"
                if self.redis.set(key, value, nx=True, ex=ttl_seconds):
                    return True, ReplayOutcome.ACCEPTED
                return False, self._classify(self.redis.get(key), binding)
            except Exception:
                # Fall through to the in-memory path on any Redis failure,
                # exactly as before.
                pass

        self._cleanup()
        now = time.time()
        if jti in self._in_memory and self._in_memory[jti] > now:
            return False, self._classify(self._in_memory_bindings.get(jti), binding)
        self._in_memory[jti] = now + ttl_seconds
        self._in_memory_bindings[jti] = value
        return True, ReplayOutcome.ACCEPTED

    @staticmethod
    def _classify(stored: Optional[str], presented: Optional[str]) -> ReplayOutcome:
        # Without a binding on either side there is nothing to compare, so the
        # honest answer is that the two cases cannot be separated.
        if presented is None or stored is None or stored == _NO_BINDING:
            return ReplayOutcome.REPLAY_UNCLASSIFIED
        return (
            ReplayOutcome.REPLAY
            if stored == presented
            else ReplayOutcome.SUBSTITUTION
        )

    def check_and_store(
        self,
        jti: str,
        ttl_seconds: int = 60,
        binding: Optional[str] = None,
    ) -> bool:
        """
        Returns True if jti is new and stored, False if replay detected.

        Unchanged contract. Callers wanting to tell a replay from a
        substitution should use check_and_classify() instead.
        """
        accepted, _ = self.check_and_classify(jti, ttl_seconds, binding)
        return accepted

#!/usr/bin/env python3
"""
Blockchain-Style Audit Logger
Append-only JSON lines with SHA-256 hash chaining for tamper-evidence.
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Iterable


class AuditChainLogger:
    """Tamper-evident audit logger with hash chaining."""

    def __init__(self, log_path: str = "logs/audit_chain.jsonl"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        """Read the last entry hash from the log file, if present."""
        if not os.path.exists(self.log_path):
            return "0" * 64
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                pos = f.tell()
                if pos == 0:
                    return "0" * 64
                # Read backwards to find the last newline
                buffer = b""
                while pos > 0:
                    pos -= 1
                    f.seek(pos)
                    byte = f.read(1)
                    if byte == b"\n" and buffer:
                        break
                    buffer = byte + buffer
                if not buffer:
                    return "0" * 64
                last_entry = json.loads(buffer.decode("utf-8"))
                return last_entry.get("hash", "0" * 64)
        except Exception:
            return "0" * 64

    def _compute_hash(self, entry: Dict[str, Any]) -> str:
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def log_event(
        self,
        event_type: str,
        agent_id: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        source_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """Append an audit event with hash chaining."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "agent_id": agent_id,
            "status": status,
            "severity": severity,
            "details": details or {},
            "source_ip": source_ip,
            "previous_hash": self._last_hash
        }
        entry_hash = self._compute_hash(entry)
        entry["hash"] = entry_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

        self._last_hash = entry_hash
        return entry

    def iter_events(self) -> Iterable[Dict[str, Any]]:
        """Yield all audit events in order."""
        if not os.path.exists(self.log_path):
            return
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> bool:
        """Verify the integrity of the audit chain."""
        prev_hash = "0" * 64
        for entry in self.iter_events():
            entry_copy = dict(entry)
            entry_hash = entry_copy.pop("hash", "")
            if entry_copy.get("previous_hash") != prev_hash:
                return False
            computed = self._compute_hash(entry_copy)
            if computed != entry_hash:
                return False
            prev_hash = entry_hash
        return True

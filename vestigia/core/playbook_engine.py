#!/usr/bin/env python3
"""
Phase 5: Automated incident playbooks (YAML-driven).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:
    yaml = None


class PlaybookStore:
    def __init__(self, path: str = "config/playbooks/defaults.yml"):
        self.path = Path(path)

    def load(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        text = self.path.read_text()
        if yaml:
            return yaml.safe_load(text) or []
        # Fallback: allow JSON if yaml is missing
        return json.loads(text)


class PlaybookExecutionStore:
    def __init__(self, path: str = "data/playbook_executions.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dsn = os.getenv("VESTIGIA_DB_DSN")
        if not self.path.exists():
            self.path.write_text(json.dumps({"executions": []}, indent=2))

    def record(self, payload: Dict[str, Any]):
        if self.dsn:
            self._record_db(payload)
            return
        data = json.loads(self.path.read_text())
        data["executions"].append(payload)
        self.path.write_text(json.dumps(data, indent=2))

    def _record_db(self, payload: Dict[str, Any]):
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO playbook_executions
                        (playbook_name, actor_id, trigger_reason, status, details)
                        VALUES (%s, %s, %s, %s, %s::jsonb)
                        """,
                        (
                            payload.get("playbook_name"),
                            payload.get("actor_id"),
                            payload.get("trigger_reason"),
                            payload.get("status", "executed"),
                            json.dumps(payload.get("details", {})),
                        ),
                    )
                conn.commit()
        except Exception:
            pass


class PlaybookEngine:
    def __init__(self, store: Optional[PlaybookStore] = None, execution_store: Optional[PlaybookExecutionStore] = None):
        self.store = store or PlaybookStore()
        self.execution_store = execution_store or PlaybookExecutionStore()
        self.webhook = os.getenv("VESTIGIA_PLAYBOOK_WEBHOOK")

    def match(self, event: Dict[str, Any], risk_score: float) -> List[Dict[str, Any]]:
        playbooks = self.store.load()
        matched = []
        for pb in playbooks:
            triggers = pb.get("trigger", {})
            if not triggers:
                continue
            if triggers.get("min_risk") and risk_score < float(triggers["min_risk"]):
                continue
            if triggers.get("action_type") and event.get("action_type") != triggers["action_type"]:
                continue
            if triggers.get("status") and str(event.get("status")).upper() != str(triggers["status"]).upper():
                continue
            matched.append(pb)
        return matched

    def execute(self, playbook: Dict[str, Any], event: Dict[str, Any], risk_score: float) -> Dict[str, Any]:
        actions = playbook.get("steps", [])
        results = []
        for step in actions:
            results.append({"step": step, "status": "completed"})

        payload = {
            "playbook_name": playbook.get("name"),
            "actor_id": event.get("actor_id"),
            "trigger_reason": playbook.get("description", ""),
            "status": "executed",
            "details": {
                "risk_score": risk_score,
                "actions": actions,
                "event": {
                    "event_id": event.get("event_id"),
                    "action_type": event.get("action_type"),
                    "status": event.get("status"),
                },
            },
            "executed_at": datetime.now(UTC).isoformat(),
        }
        self.execution_store.record(payload)
        self._notify_webhook(payload)
        return payload

    def _notify_webhook(self, payload: Dict[str, Any]):
        if not self.webhook:
            return
        try:
            import httpx
            httpx.post(self.webhook, json=payload, timeout=5.0)
        except Exception:
            pass

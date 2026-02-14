#!/usr/bin/env python3
"""
Phase 5: ML-inspired anomaly detection (baseline + z-score + rules).
Designed to work without external ML dependencies while allowing upgrade later.
"""

from __future__ import annotations

import json
import math
import os
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Any, Optional

from core.feature_engineering import extract_features
from core.anomaly_models import IsolationForestLite, OneClassSVMLite, SequenceModelLite

class BaselineStore:
    """Persistent baseline store for per-actor metrics (file or Postgres)."""

    def __init__(self, path: str = "data/anomaly_baselines.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dsn = os.getenv("VESTIGIA_DB_DSN")
        if not self.path.exists():
            self.path.write_text(json.dumps({"actors": {}, "feedback": []}, indent=2))

    def load(self) -> Dict[str, Any]:
        if self.dsn:
            return self._load_db()
        return json.loads(self.path.read_text())

    def save(self, data: Dict[str, Any]):
        if self.dsn:
            self._save_db(data)
            return
        self.path.write_text(json.dumps(data, indent=2))

    def _load_db(self) -> Dict[str, Any]:
        actors = {}
        feedback = []
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT actor_id, avg_events_per_hour, avg_payload_size,
                               hour_bucket_start, hour_count, tools, last_seen
                        FROM anomaly_baselines
                        """
                    )
                    for row in cur.fetchall():
                        actors[row[0]] = {
                            "count": 0,
                            "avg_events_per_hour": row[1] or 0.0,
                            "avg_payload_size": row[2] or 0.0,
                            "hour_bucket_start": row[3].isoformat() if row[3] else None,
                            "hour_count": row[4] or 0,
                            "tools": row[5] or {},
                            "last_seen": row[6].isoformat() if row[6] else None,
                        }
                    cur.execute(
                        "SELECT event_id, actor_id, label, note FROM anomaly_feedback"
                    )
                    feedback = [
                        {"event_id": r[0], "actor_id": r[1], "label": r[2], "note": r[3]}
                        for r in cur.fetchall()
                    ]
        except Exception:
            pass
        return {"actors": actors, "feedback": feedback}

    def _save_db(self, data: Dict[str, Any]):
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    for actor_id, actor in data.get("actors", {}).items():
                        cur.execute(
                            """
                            INSERT INTO anomaly_baselines
                            (actor_id, avg_events_per_hour, avg_payload_size, hour_bucket_start, hour_count, tools, last_seen)
                            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
                            ON CONFLICT (actor_id) DO UPDATE SET
                              avg_events_per_hour = EXCLUDED.avg_events_per_hour,
                              avg_payload_size = EXCLUDED.avg_payload_size,
                              hour_bucket_start = EXCLUDED.hour_bucket_start,
                              hour_count = EXCLUDED.hour_count,
                              tools = EXCLUDED.tools,
                              last_seen = EXCLUDED.last_seen
                            """,
                            (
                                actor_id,
                                actor.get("avg_events_per_hour", 0.0),
                                actor.get("avg_payload_size", 0.0),
                                actor.get("hour_bucket_start"),
                                actor.get("hour_count", 0),
                                json.dumps(actor.get("tools", {})),
                                actor.get("last_seen"),
                            ),
                        )
                    for fb in data.get("feedback", []):
                        if not fb.get("event_id"):
                            continue
                        cur.execute(
                            """
                            INSERT INTO anomaly_feedback (event_id, actor_id, label, note)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            (fb.get("event_id"), fb.get("actor_id"), fb.get("label"), fb.get("note")),
                        )
                conn.commit()
        except Exception:
            pass


class AnomalyDetector:
    """
    Lightweight anomaly detection:
    - Baseline metrics per actor
    - Z-score on event rate and data volume
    - Rule-based checks (off-hours, spikes, unusual tool)
    """

    def __init__(self, store: Optional[BaselineStore] = None):
        self.store = store or BaselineStore()
        self._model_iforest = IsolationForestLite()
        self._model_ocsvm = OneClassSVMLite()
        self._model_seq = SequenceModelLite()

    def update_baseline(self, actor_id: str, event: Dict[str, Any]):
        data = self.store.load()
        actors = data.setdefault("actors", {})
        actor = actors.setdefault(actor_id, {
            "count": 0,
            "avg_events_per_hour": 0.0,
            "avg_payload_size": 0.0,
            "tools": {},
            "transitions": {},
            "last_action": None,
            "mean_features": {},
            "scale_features": {},
            "radius": 1.0,
            "last_seen": None
        })

        actor["count"] += 1
        payload_size = len(json.dumps(event.get("evidence", {})))
        actor["avg_payload_size"] = self._ema(actor["avg_payload_size"], payload_size)

        tool = event.get("action_type", "UNKNOWN")
        actor["tools"][tool] = actor["tools"].get(tool, 0) + 1
        if actor.get("last_action"):
            transitions = actor.setdefault("transitions", {})
            transitions.setdefault(actor["last_action"], {})
            transitions[actor["last_action"]][tool] = transitions[actor["last_action"]].get(tool, 0) + 1
        actor["last_action"] = tool

        features, meta = extract_features(event)
        # Update mean/scale for feature-based models
        for key, value in features.items():
            prev = actor["mean_features"].get(key, value)
            actor["mean_features"][key] = self._ema(prev, value)
            prev_scale = actor["scale_features"].get(key, 1.0)
            actor["scale_features"][key] = self._ema(prev_scale, abs(value - actor["mean_features"][key]) + 1.0)

        # Update novelty radius heuristic
        actor["radius"] = max(1.0, actor.get("radius", 1.0) * 0.98 + 0.02 * sum(features.values()) / max(1.0, len(features)))

        now = datetime.now(UTC)
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        if actor.get("hour_bucket_start") != hour_start.isoformat():
            # close prior hour
            prior_count = actor.get("hour_count", 0)
            actor["avg_events_per_hour"] = self._ema(actor["avg_events_per_hour"], float(prior_count))
            actor["hour_bucket_start"] = hour_start.isoformat()
            actor["hour_count"] = 1
        else:
            actor["hour_count"] = actor.get("hour_count", 0) + 1

        actor["last_seen"] = now.isoformat()
        self.store.save(data)

    def score_event(self, actor_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        data = self.store.load()
        actor = data.get("actors", {}).get(actor_id)
        feedback = data.get("feedback", [])
        event_id = event.get("event_id")
        if event_id and any(f.get("event_id") == event_id and f.get("label") == "benign" for f in feedback):
            return {"risk_score": 0.0, "reason": "benign_feedback", "signals": []}
        if not actor:
            # No baseline yet, allow and build
            self.update_baseline(actor_id, event)
            return {"risk_score": 10.0, "reason": "baseline_initialized", "signals": []}

        signals = []
        risk = 0.0

        features, meta = extract_features(event)

        payload_size = len(json.dumps(event.get("evidence", {})))
        if actor["avg_payload_size"] > 0:
            z = (payload_size - actor["avg_payload_size"]) / max(1.0, actor["avg_payload_size"])
            if z > 3:
                signals.append("payload_spike")
                risk += 20

        # Off-hours check
        now = datetime.now(UTC)
        if now.hour < 6 or now.hour > 22:
            signals.append("off_hours_activity")
            risk += 15

        # Unusual tool usage
        tool = event.get("action_type", "UNKNOWN")
        if tool not in actor.get("tools", {}):
            signals.append("new_tool")
            risk += 10

        # Rate-per-hour spike
        avg_rate = actor.get("avg_events_per_hour", 0.0)
        hour_count = actor.get("hour_count", 0) + 1
        if avg_rate > 0 and hour_count > (avg_rate * 3):
            signals.append("rate_spike")
            risk += 25

        # Critical status boost
        if event.get("status", "").upper() in ("CRITICAL", "BLOCKED"):
            signals.append("critical_status")
            risk += 30

        # Model ensemble scores
        baseline = actor
        self._model_iforest.fit(baseline)
        self._model_ocsvm.fit(baseline)
        self._model_seq.fit(baseline)

        iforest_score, iforest_signals = self._model_iforest.score(features)
        ocsvm_score, ocsvm_signals = self._model_ocsvm.score(features)
        seq_score, seq_signals = self._model_seq.score(tool, actor.get("last_action"))

        risk += (iforest_score * 0.4) + (ocsvm_score * 0.4) + (seq_score * 0.2)
        signals.extend(iforest_signals + ocsvm_signals + seq_signals)

        # Cap risk
        risk = min(100.0, risk)

        return {"risk_score": risk, "reason": "anomaly_scored", "signals": signals}

    def record_feedback(self, event_id: str, actor_id: str, label: str = "benign", note: str = ""):
        data = self.store.load()
        feedback = data.setdefault("feedback", [])
        feedback.append({"event_id": event_id, "actor_id": actor_id, "label": label, "note": note})
        self.store.save(data)

    def retrain(self):
        """
        Retrain baselines by re-normalizing averages from stored baselines.
        This is a lightweight loop intended to be called periodically.
        """
        data = self.store.load()
        for actor_id, actor in data.get("actors", {}).items():
            # Decay counts to keep model responsive
            actor["avg_events_per_hour"] = max(0.0, actor.get("avg_events_per_hour", 0.0) * 0.95)
            actor["avg_payload_size"] = max(0.0, actor.get("avg_payload_size", 0.0) * 0.95)
            actor["hour_count"] = int(actor.get("hour_count", 0) * 0.5)
        self.store.save(data)

    @staticmethod
    def _ema(old: float, new: float, alpha: float = 0.1) -> float:
        if old == 0.0:
            return new
        return (alpha * new) + ((1 - alpha) * old)

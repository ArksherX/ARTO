#!/usr/bin/env python3
"""
Phase 5: Predictive risk forecasting.
Simple exponential smoothing + trend extrapolation (dependency-free).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional


class RiskHistoryStore:
    def __init__(self, path: str = "data/risk_history.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dsn = os.getenv("VESTIGIA_DB_DSN")
        if not self.path.exists():
            self.path.write_text(json.dumps({"history": []}, indent=2))

    def append(self, actor_id: str, event_id: Optional[str], risk_score: float, signals: List[str]):
        if self.dsn:
            self._append_db(actor_id, event_id, risk_score, signals)
            return
        data = json.loads(self.path.read_text())
        data["history"].append({
            "actor_id": actor_id,
            "event_id": event_id,
            "risk_score": risk_score,
            "signals": signals,
            "recorded_at": datetime.now(UTC).isoformat()
        })
        self.path.write_text(json.dumps(data, indent=2))

    def query(self, actor_id: str, days: int = 30) -> List[Dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(days=days)
        if self.dsn:
            return self._query_db(actor_id, since)
        data = json.loads(self.path.read_text())
        results = []
        for entry in data.get("history", []):
            if entry.get("actor_id") != actor_id:
                continue
            try:
                ts = datetime.fromisoformat(entry.get("recorded_at"))
            except Exception:
                continue
            if ts >= since:
                results.append(entry)
        return results

    def _append_db(self, actor_id: str, event_id: Optional[str], risk_score: float, signals: List[str]):
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO risk_history (actor_id, event_id, risk_score, signals)
                        VALUES (%s, %s, %s, %s::jsonb)
                        """,
                        (actor_id, event_id, risk_score, json.dumps(signals)),
                    )
                conn.commit()
        except Exception:
            pass

    def _query_db(self, actor_id: str, since: datetime) -> List[Dict[str, Any]]:
        results = []
        try:
            import psycopg2
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT event_id, risk_score, signals, recorded_at
                        FROM risk_history
                        WHERE actor_id = %s AND recorded_at >= %s
                        ORDER BY recorded_at ASC
                        """,
                        (actor_id, since),
                    )
                    for row in cur.fetchall():
                        results.append({
                            "actor_id": actor_id,
                            "event_id": row[0],
                            "risk_score": row[1],
                            "signals": row[2] or [],
                            "recorded_at": row[3].isoformat() if row[3] else None,
                        })
        except Exception:
            pass
        return results


class RiskForecaster:
    def __init__(self, store: Optional[RiskHistoryStore] = None):
        self.store = store or RiskHistoryStore()

    def forecast(self, actor_id: str, horizon_hours: int = 24) -> Dict[str, Any]:
        history = self.store.query(actor_id, days=30)
        if len(history) < 3:
            return {
                "actor_id": actor_id,
                "forecast_horizon": f"{horizon_hours}h",
                "predicted_risk": 0.0,
                "confidence_interval": (0.0, 25.0),
                "recommendation": "Insufficient history for forecasting",
            }

        scores = [float(h["risk_score"]) for h in history]
        # Simple trend: last - first over window
        trend = (scores[-1] - scores[0]) / max(1, len(scores) - 1)
        baseline = sum(scores[-10:]) / max(1, min(10, len(scores)))
        predicted = max(0.0, min(100.0, baseline + (trend * (horizon_hours / 6))))

        spread = max(5.0, abs(trend) * 10.0)
        lower = max(0.0, predicted - spread)
        upper = min(100.0, predicted + spread)

        recommendation = "Risk stable"
        if predicted >= 80:
            recommendation = "Preemptive containment recommended"
        elif predicted >= 60:
            recommendation = "Increase monitoring and require approvals"

        return {
            "actor_id": actor_id,
            "forecast_horizon": f"{horizon_hours}h",
            "predicted_risk": round(predicted, 2),
            "confidence_interval": (round(lower, 2), round(upper, 2)),
            "recommendation": recommendation,
        }

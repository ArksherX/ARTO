#!/usr/bin/env python3
"""
Phase 5: Natural language query interface (rule-based, safe).
Transforms simple NL prompts into ledger filters and post-filters.
"""

from __future__ import annotations

import re
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, List, Optional


class NLQueryEngine:
    def __init__(self):
        self._agent_re = re.compile(r"(agent|actor)\s+([a-zA-Z0-9_\-]+)", re.IGNORECASE)

    def parse(self, query: str) -> Dict[str, Any]:
        q = query.lower()
        filters: Dict[str, Any] = {}
        post_filters: Dict[str, Any] = {}

        match = self._agent_re.search(q)
        if match:
            filters["actor_id"] = match.group(2)

        if "blocked" in q:
            filters["status"] = "BLOCKED"
        elif "critical" in q:
            filters["status"] = "CRITICAL"
        elif "warning" in q:
            filters["status"] = "WARNING"

        if "last 24 hours" in q or "past 24 hours" in q:
            filters["start_date"] = datetime.now(UTC) - timedelta(hours=24)
        elif "last week" in q or "past week" in q:
            filters["start_date"] = datetime.now(UTC) - timedelta(days=7)
        elif "yesterday" in q:
            start = datetime.now(UTC) - timedelta(days=1)
            filters["start_date"] = start.replace(hour=0, minute=0, second=0, microsecond=0)
            filters["end_date"] = start.replace(hour=23, minute=59, second=59, microsecond=0)

        if "high risk" in q or "high-risk" in q:
            post_filters["min_anomaly_risk"] = 70

        if "after hours" in q or "off hours" in q:
            post_filters["off_hours"] = True

        return {"filters": filters, "post_filters": post_filters}

    def apply(self, events: List[Dict[str, Any]], post_filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = events
        min_risk = post_filters.get("min_anomaly_risk")
        if min_risk is not None:
            results = [
                e for e in results
                if float((e.get("evidence") or {}).get("anomaly_risk", 0)) >= float(min_risk)
            ]

        if post_filters.get("off_hours"):
            filtered = []
            for e in results:
                try:
                    ts = datetime.fromisoformat(e.get("timestamp"))
                    if ts.hour < 6 or ts.hour > 22:
                        filtered.append(e)
                except Exception:
                    continue
            results = filtered

        return results

#!/usr/bin/env python3
"""
Phase 6: SLA monitoring for Vestigia SaaS.

Tracks uptime/availability, records service incidents, computes SLA compliance
percentage, MTTD, MTTR, and provides incident transparency data for the status page.

Target: 99.99% uptime SLA (≤52.6 minutes downtime/year).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import uuid


SLA_TARGETS = {
    "free":       {"uptime_pct": 99.0,   "response_minutes": 240, "resolution_hours": 48},
    "pro":        {"uptime_pct": 99.9,   "response_minutes": 60,  "resolution_hours": 8},
    "enterprise": {"uptime_pct": 99.99,  "response_minutes": 15,  "resolution_hours": 2},
}

COMPONENT_NAMES = ["api", "ledger", "anomaly_engine", "siem_forwarder", "dashboard"]


class SLAMonitor:
    """Record availability checks, incidents, and calculate SLA compliance."""

    def __init__(self, data_dir: str = "data"):
        self.path = Path(data_dir) / "sla_records.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({
                "health_checks": [],   # [{ts, component, healthy, latency_ms}]
                "incidents": [],       # [{id, component, severity, started, resolved, ...}]
            }, indent=2))

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {"health_checks": [], "incidents": []}

    def _save(self, data: Dict[str, Any]) -> None:
        # Keep only last 10 000 health checks to prevent unbounded growth
        if len(data.get("health_checks", [])) > 10_000:
            data["health_checks"] = data["health_checks"][-10_000:]
        self.path.write_text(json.dumps(data, indent=2, default=str))

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def record_health_check(
        self,
        component: str,
        healthy: bool,
        latency_ms: Optional[float] = None,
        detail: Optional[str] = None,
    ) -> None:
        """Record a single availability probe result."""
        data = self._load()
        data["health_checks"].append({
            "ts": datetime.now(UTC).isoformat(),
            "component": component,
            "healthy": healthy,
            "latency_ms": latency_ms,
            "detail": detail,
        })
        self._save(data)

    def record_bulk_health_check(self, results: Dict[str, bool]) -> None:
        """Record health checks for multiple components at once."""
        for comp, healthy in results.items():
            self.record_health_check(comp, healthy)

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(
        self,
        component: str,
        severity: str,          # critical | high | medium | low
        title: str,
        description: str = "",
        tenant_plan: str = "pro",
    ) -> Dict[str, Any]:
        """Open a new service incident."""
        data = self._load()
        incident = {
            "id": f"INC-{uuid.uuid4().hex[:8].upper()}",
            "component": component,
            "severity": severity,
            "title": title,
            "description": description,
            "status": "investigating",       # investigating | identified | monitoring | resolved
            "started_at": datetime.now(UTC).isoformat(),
            "identified_at": None,
            "resolved_at": None,
            "sla_target": SLA_TARGETS.get(tenant_plan, SLA_TARGETS["pro"]),
            "updates": [],
        }
        data["incidents"].append(incident)
        self._save(data)
        return incident

    def update_incident(self, incident_id: str, status: str, update_text: str) -> Optional[Dict[str, Any]]:
        """Add a status update to an incident."""
        data = self._load()
        now = datetime.now(UTC).isoformat()
        for inc in data["incidents"]:
            if inc["id"] == incident_id:
                inc["status"] = status
                inc["updates"].append({"ts": now, "status": status, "text": update_text})
                if status == "identified" and not inc.get("identified_at"):
                    inc["identified_at"] = now
                if status == "resolved" and not inc.get("resolved_at"):
                    inc["resolved_at"] = now
                self._save(data)
                return inc
        return None

    def resolve_incident(self, incident_id: str, resolution_text: str = "Issue resolved.") -> Optional[Dict[str, Any]]:
        return self.update_incident(incident_id, "resolved", resolution_text)

    # ------------------------------------------------------------------
    # Metrics computation
    # ------------------------------------------------------------------

    def get_sla_metrics(self, window_days: int = 30, plan: str = "pro") -> Dict[str, Any]:
        """
        Compute SLA compliance metrics over the given window.

        Returns uptime %, MTTD, MTTR, incident count, SLA breach status.
        """
        data = self._load()
        target = SLA_TARGETS.get(plan, SLA_TARGETS["pro"])
        cutoff = (datetime.now(UTC) - timedelta(days=window_days)).isoformat()

        # --- Uptime from health checks ---
        checks = [c for c in data["health_checks"] if c.get("ts", "") >= cutoff]
        total_checks = len(checks)
        healthy_checks = sum(1 for c in checks if c.get("healthy", True))
        uptime_pct = round(100 * healthy_checks / max(1, total_checks), 4)

        # Per-component uptime
        component_stats: Dict[str, Dict[str, int]] = {}
        for c in checks:
            comp = c.get("component", "unknown")
            if comp not in component_stats:
                component_stats[comp] = {"total": 0, "healthy": 0}
            component_stats[comp]["total"] += 1
            if c.get("healthy", True):
                component_stats[comp]["healthy"] += 1

        component_uptime = {
            comp: round(100 * s["healthy"] / max(1, s["total"]), 2)
            for comp, s in component_stats.items()
        }

        # --- Incidents in window ---
        incidents = [i for i in data["incidents"] if i.get("started_at", "") >= cutoff]
        resolved = [i for i in incidents if i.get("resolved_at")]

        # MTTD = time from incident start to identified_at
        mttd_mins: List[float] = []
        mttr_mins: List[float] = []
        for inc in resolved:
            try:
                start = datetime.fromisoformat(inc["started_at"])
                if inc.get("identified_at"):
                    ident = datetime.fromisoformat(inc["identified_at"])
                    mttd_mins.append((ident - start).total_seconds() / 60)
                res = datetime.fromisoformat(inc["resolved_at"])
                mttr_mins.append((res - start).total_seconds() / 60)
            except Exception:
                pass

        avg_mttd = round(sum(mttd_mins) / len(mttd_mins), 1) if mttd_mins else 0
        avg_mttr = round(sum(mttr_mins) / len(mttr_mins), 1) if mttr_mins else 0

        # SLA compliance
        sla_met = uptime_pct >= target["uptime_pct"]
        sla_gap = round(uptime_pct - target["uptime_pct"], 4)

        return {
            "window_days": window_days,
            "plan": plan,
            "target": target,
            "uptime_pct": uptime_pct,
            "sla_met": sla_met,
            "sla_gap_pct": sla_gap,
            "total_checks": total_checks,
            "component_uptime": component_uptime,
            "incidents": {
                "total": len(incidents),
                "resolved": len(resolved),
                "open": len(incidents) - len(resolved),
                "by_severity": _count_by(incidents, "severity"),
            },
            "mttd_minutes": avg_mttd,
            "mttr_minutes": avg_mttr,
            "computed_at": datetime.now(UTC).isoformat(),
        }

    def get_incident_transparency(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent incidents for the public status page."""
        data = self._load()
        incidents = sorted(data["incidents"], key=lambda i: i.get("started_at", ""), reverse=True)
        return incidents[:limit]

    def get_status_summary(self) -> Dict[str, Any]:
        """Return current system status suitable for a status page header."""
        data = self._load()
        # Look at health checks from last 5 minutes
        cutoff = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        recent = [c for c in data["health_checks"] if c.get("ts", "") >= cutoff]
        open_incidents = [i for i in data["incidents"] if i.get("status") not in ("resolved",)]

        if not recent:
            overall = "unknown"
        elif all(c.get("healthy", True) for c in recent):
            overall = "operational"
        elif sum(1 for c in recent if not c.get("healthy")) / len(recent) > 0.5:
            overall = "major_outage"
        else:
            overall = "partial_outage"

        per_component: Dict[str, str] = {}
        for comp in COMPONENT_NAMES:
            comp_checks = [c for c in recent if c.get("component") == comp]
            if not comp_checks:
                per_component[comp] = "unknown"
            elif all(c.get("healthy", True) for c in comp_checks):
                per_component[comp] = "operational"
            else:
                per_component[comp] = "degraded"

        return {
            "overall": overall,
            "components": per_component,
            "open_incidents": len(open_incidents),
            "checked_at": datetime.now(UTC).isoformat(),
        }


def _count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for item in items:
        v = item.get(key, "unknown")
        result[v] = result.get(v, 0) + 1
    return result

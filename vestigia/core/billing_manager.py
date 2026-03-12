#!/usr/bin/env python3
"""
Phase 6 — Billing Manager.
Tracks plan usage, enforces limits, records billing events, and computes SLA metrics.
Works alongside tenant_manager.py — billing_manager reads tenant plans and records usage.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List


PLAN_DEFINITIONS = {
    "free": {
        "events_per_day": 1000,
        "events_per_month": 10000,
        "users_max": 5,
        "retention_days": 7,
        "price_usd_month": 0,
        "features": ["basic_dashboard", "community_support"],
    },
    "pro": {
        "events_per_day": 10000,
        "events_per_month": 100000,
        "users_max": 50,
        "retention_days": 90,
        "price_usd_month": 99,
        "features": ["advanced_analytics", "email_support", "siem_integration", "anomaly_detection"],
    },
    "enterprise": {
        "events_per_day": 100000,
        "events_per_month": -1,  # unlimited
        "users_max": 500,
        "retention_days": 365,
        "price_usd_month": -1,  # custom pricing
        "features": ["all", "hsm_signing", "blockchain_anchoring", "dedicated_support", "sla_guarantee"],
    },
}

SLA_TARGETS = {
    "free": 0.99,        # 99%
    "pro": 0.999,        # 99.9%
    "enterprise": 0.9999,  # 99.99%
}


class BillingManager:
    """Manages plan limits, usage tracking, billing events, and SLA metrics."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._usage_path = self.data_dir / "billing_usage.json"
        self._events_path = self.data_dir / "billing_events.json"
        self._sla_path = self.data_dir / "sla_metrics.json"
        self._ensure_files()

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def _today(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m-%d")

    def _month(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m")

    def _ensure_files(self):
        for path, default in [
            (self._usage_path, {}),
            (self._events_path, []),
            (self._sla_path, {}),
        ]:
            if not path.exists():
                path.write_text(json.dumps(default, indent=2))

    def _load_usage(self) -> Dict[str, Any]:
        try:
            return json.loads(self._usage_path.read_text())
        except Exception:
            return {}

    def _save_usage(self, data: Dict[str, Any]):
        self._usage_path.write_text(json.dumps(data, indent=2))

    def _load_events(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self._events_path.read_text())
        except Exception:
            return []

    def _save_events(self, events: List[Dict[str, Any]]):
        self._events_path.write_text(json.dumps(events[-5000:], indent=2))  # keep last 5000

    def _load_sla(self) -> Dict[str, Any]:
        try:
            return json.loads(self._sla_path.read_text())
        except Exception:
            return {}

    def _save_sla(self, data: Dict[str, Any]):
        self._sla_path.write_text(json.dumps(data, indent=2))

    # ──────────────────────────────────────────────────────────────────
    # Usage tracking
    # ──────────────────────────────────────────────────────────────────

    def record_event_ingested(self, tenant_id: str, plan: str = "free") -> Dict[str, Any]:
        """Called each time an event is ingested. Returns limit check result."""
        usage = self._load_usage()
        today = self._today()
        month = self._month()

        tenant_usage = usage.setdefault(tenant_id, {})
        day_key = f"day_{today}"
        month_key = f"month_{month}"
        tenant_usage[day_key] = tenant_usage.get(day_key, 0) + 1
        tenant_usage[month_key] = tenant_usage.get(month_key, 0) + 1
        tenant_usage["total"] = tenant_usage.get("total", 0) + 1
        tenant_usage["plan"] = plan
        tenant_usage["last_event"] = self._now()

        self._save_usage(usage)

        limits = PLAN_DEFINITIONS.get(plan, PLAN_DEFINITIONS["free"])
        day_limit = limits["events_per_day"]
        month_limit = limits["events_per_month"]

        day_count = tenant_usage[day_key]
        month_count = tenant_usage[month_key]

        over_day = day_limit > 0 and day_count > day_limit
        over_month = month_limit > 0 and month_count > month_limit

        if over_day or over_month:
            self._record_billing_event(tenant_id, "LIMIT_EXCEEDED", {
                "day_count": day_count, "day_limit": day_limit,
                "month_count": month_count, "month_limit": month_limit,
                "plan": plan,
            })

        return {
            "tenant_id": tenant_id,
            "plan": plan,
            "day_count": day_count,
            "day_limit": day_limit,
            "month_count": month_count,
            "month_limit": month_limit,
            "over_day_limit": over_day,
            "over_month_limit": over_month,
            "allowed": not (over_day or over_month),
        }

    def check_plan_limits(self, tenant_id: str, plan: str = "free") -> Dict[str, Any]:
        """Check current usage against plan limits without incrementing."""
        usage = self._load_usage()
        tenant_usage = usage.get(tenant_id, {})
        today = self._today()
        month = self._month()

        limits = PLAN_DEFINITIONS.get(plan, PLAN_DEFINITIONS["free"])
        day_count = tenant_usage.get(f"day_{today}", 0)
        month_count = tenant_usage.get(f"month_{month}", 0)

        return {
            "tenant_id": tenant_id,
            "plan": plan,
            "plan_definition": limits,
            "usage": {
                "today": day_count,
                "this_month": month_count,
                "total_all_time": tenant_usage.get("total", 0),
            },
            "limits": {
                "events_per_day": limits["events_per_day"],
                "events_per_month": limits["events_per_month"],
            },
            "utilization": {
                "day_pct": (day_count / limits["events_per_day"] * 100) if limits["events_per_day"] > 0 else 0,
                "month_pct": (month_count / limits["events_per_month"] * 100) if limits["events_per_month"] > 0 else 0,
            },
            "over_limit": (limits["events_per_day"] > 0 and day_count > limits["events_per_day"])
                          or (limits["events_per_month"] > 0 and month_count > limits["events_per_month"]),
        }

    def get_usage_report(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get usage report for a tenant or all tenants."""
        usage = self._load_usage()
        today = self._today()
        month = self._month()
        if tenant_id:
            tenants = {tenant_id: usage.get(tenant_id, {})}
        else:
            tenants = usage
        report = {}
        for tid, tdata in tenants.items():
            plan = tdata.get("plan", "free")
            limits = PLAN_DEFINITIONS.get(plan, PLAN_DEFINITIONS["free"])
            report[tid] = {
                "plan": plan,
                "today": tdata.get(f"day_{today}", 0),
                "this_month": tdata.get(f"month_{month}", 0),
                "total": tdata.get("total", 0),
                "last_event": tdata.get("last_event"),
                "day_limit": limits["events_per_day"],
                "month_limit": limits["events_per_month"],
            }
        return report

    # ──────────────────────────────────────────────────────────────────
    # Billing events
    # ──────────────────────────────────────────────────────────────────

    def _record_billing_event(self, tenant_id: str, event_type: str, details: Dict[str, Any]):
        events = self._load_events()
        events.append({
            "timestamp": self._now(),
            "tenant_id": tenant_id,
            "event_type": event_type,
            "details": details,
        })
        self._save_events(events)

    def record_plan_change(self, tenant_id: str, old_plan: str, new_plan: str, changed_by: str = "admin"):
        """Record a plan upgrade/downgrade event."""
        self._record_billing_event(tenant_id, "PLAN_CHANGED", {
            "old_plan": old_plan,
            "new_plan": new_plan,
            "changed_by": changed_by,
        })

    def get_billing_events(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get billing events (plan changes, limit breaches) for a tenant or all."""
        events = self._load_events()
        if tenant_id:
            events = [e for e in events if e.get("tenant_id") == tenant_id]
        return events[-limit:]

    # ──────────────────────────────────────────────────────────────────
    # SLA monitoring
    # ──────────────────────────────────────────────────────────────────

    def record_health_check(self, is_up: bool, response_time_ms: float = 0.0):
        """Record a health check result for SLA tracking."""
        sla = self._load_sla()
        today = self._today()
        month = self._month()

        day_data = sla.setdefault(f"day_{today}", {"checks": 0, "up": 0, "total_ms": 0.0})
        month_data = sla.setdefault(f"month_{month}", {"checks": 0, "up": 0})

        day_data["checks"] += 1
        month_data["checks"] += 1
        if is_up:
            day_data["up"] += 1
            month_data["up"] += 1
        day_data["total_ms"] = day_data.get("total_ms", 0.0) + response_time_ms
        sla["last_check"] = self._now()
        sla["last_status"] = "up" if is_up else "down"

        self._save_sla(sla)

    def compute_sla_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Compute SLA metrics over the past N days."""
        sla = self._load_sla()
        total_checks = 0
        total_up = 0
        total_ms = 0.0
        incidents = 0

        for i in range(days):
            day = (datetime.now(UTC) - timedelta(days=i)).strftime("%Y-%m-%d")
            day_data = sla.get(f"day_{day}", {})
            checks = day_data.get("checks", 0)
            up = day_data.get("up", 0)
            total_checks += checks
            total_up += up
            total_ms += day_data.get("total_ms", 0.0)
            if checks > 0 and (up / checks) < 0.99:
                incidents += 1

        uptime_pct = (total_up / total_checks * 100) if total_checks > 0 else 100.0
        avg_response_ms = (total_ms / total_up) if total_up > 0 else 0.0

        return {
            "period_days": days,
            "total_checks": total_checks,
            "uptime_pct": round(uptime_pct, 4),
            "downtime_minutes": round((total_checks - total_up) * 1.0, 1),
            "avg_response_ms": round(avg_response_ms, 1),
            "incidents": incidents,
            "last_check": sla.get("last_check"),
            "last_status": sla.get("last_status", "unknown"),
            "sla_targets": SLA_TARGETS,
            "meets_enterprise_sla": uptime_pct >= 99.99,
            "meets_pro_sla": uptime_pct >= 99.9,
        }

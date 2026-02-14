#!/usr/bin/env python3
"""
Vestigia Cost Manager - Budget Tracking & Intelligent Sampling
Phase 2: Production Hardening

Reduces storage and forwarding costs by sampling low-priority events
while guaranteeing 100% capture of critical security events.
"""

import random
import time
import logging
from datetime import datetime, UTC, timedelta
from typing import Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Default cost per event (arbitrary units)
_DEFAULT_EVENT_COST = 0.001  # ~$1 per 1000 events


@dataclass
class BudgetConfig:
    monthly_budget: float = 1000.0
    alert_threshold: float = 0.80
    sampling_rates: Dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 1.0,
        "HIGH": 1.0,
        "WARNING": 0.50,
        "INFO": 0.10,
        "DEBUG": 0.01,
        # Status-based fallback
        "SUCCESS": 0.10,
        "BLOCKED": 1.0,
    })


class CostManager:
    """
    Budget tracking and intelligent event sampling.

    Ensures critical events are always recorded while reducing cost
    by probabilistically sampling lower-severity events.
    """

    def __init__(self, config: Optional[BudgetConfig] = None):
        self.config = config or BudgetConfig()
        self._current_spend: float = 0.0
        self._events_recorded: int = 0
        self._events_sampled_out: int = 0
        self._period_start: datetime = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        self._alert_sent: bool = False

    # ------------------------------------------------------------------
    # Sampling
    # ------------------------------------------------------------------

    def should_record(self, event: dict) -> bool:
        """
        Decide whether to record this event based on severity/status sampling.

        CRITICAL events are **always** recorded regardless of budget.
        """
        severity = event.get("severity", event.get("status", "INFO")).upper()

        # Always record critical / blocked
        if severity in ("CRITICAL", "BLOCKED"):
            return True

        rate = self.config.sampling_rates.get(severity, 0.10)
        decision = random.random() < rate

        if not decision:
            self._events_sampled_out += 1

        return decision

    # ------------------------------------------------------------------
    # Cost tracking
    # ------------------------------------------------------------------

    def record_cost(self, event: dict, cost: Optional[float] = None):
        """Track cumulative cost of recording an event."""
        self._maybe_reset_period()
        actual_cost = cost if cost is not None else _DEFAULT_EVENT_COST
        self._current_spend += actual_cost
        self._events_recorded += 1

        # Alert check
        pct = self._current_spend / self.config.monthly_budget if self.config.monthly_budget else 0
        if pct >= self.config.alert_threshold and not self._alert_sent:
            logger.warning(
                "Budget alert: %.1f%% of monthly budget consumed ($%.2f / $%.2f)",
                pct * 100, self._current_spend, self.config.monthly_budget,
            )
            self._alert_sent = True

    def get_budget_status(self) -> dict:
        self._maybe_reset_period()
        pct = (self._current_spend / self.config.monthly_budget * 100) if self.config.monthly_budget else 0
        return {
            "current_spend": round(self._current_spend, 2),
            "budget_limit": self.config.monthly_budget,
            "percentage_used": round(pct, 1),
            "events_recorded": self._events_recorded,
            "events_sampled_out": self._events_sampled_out,
            "period_start": self._period_start.isoformat(),
            "alert_sent": self._alert_sent,
        }

    def get_cost_projection(self, days_ahead: int = 30) -> dict:
        self._maybe_reset_period()
        elapsed = (datetime.now(UTC) - self._period_start).total_seconds() / 86400
        if elapsed < 0.01:
            daily_rate = 0.0
        else:
            daily_rate = self._current_spend / elapsed
        projected = daily_rate * days_ahead
        return {
            "daily_rate": round(daily_rate, 2),
            "projected_spend": round(projected, 2),
            "days_ahead": days_ahead,
            "over_budget": projected > self.config.monthly_budget,
        }

    def get_savings_report(self) -> dict:
        total_considered = self._events_recorded + self._events_sampled_out
        saved_cost = self._events_sampled_out * _DEFAULT_EVENT_COST
        pct = (self._events_sampled_out / total_considered * 100) if total_considered else 0
        return {
            "total_events_considered": total_considered,
            "events_recorded": self._events_recorded,
            "events_sampled_out": self._events_sampled_out,
            "sampling_reduction_pct": round(pct, 1),
            "estimated_cost_saved": round(saved_cost, 2),
        }

    # ------------------------------------------------------------------
    # Sampling rate overrides
    # ------------------------------------------------------------------

    def set_sampling_rate(self, severity: str, rate: float):
        if not 0.0 <= rate <= 1.0:
            raise ValueError("rate must be between 0.0 and 1.0")
        self.config.sampling_rates[severity.upper()] = rate

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _maybe_reset_period(self):
        """Reset counters on the 1st of each month."""
        now = datetime.now(UTC)
        period_end = (self._period_start + timedelta(days=32)).replace(day=1)
        if now >= period_end:
            logger.info("Monthly budget period reset")
            self._period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            self._current_spend = 0.0
            self._events_recorded = 0
            self._events_sampled_out = 0
            self._alert_sent = False


if __name__ == "__main__":
    cm = CostManager()
    print("Budget status:", cm.get_budget_status())

    # Simulate events
    for i in range(100):
        evt = {"severity": random.choice(["CRITICAL", "WARNING", "INFO", "INFO", "INFO", "DEBUG"])}
        if cm.should_record(evt):
            cm.record_cost(evt)

    print("After 100 events:")
    print("  Budget:", cm.get_budget_status())
    print("  Savings:", cm.get_savings_report())
    print("  Projection:", cm.get_cost_projection())

#!/usr/bin/env python3
"""
Cross-Component Event Correlator

Correlates events across Tessera, VerityFlux, and Vestigia to build
unified timelines and detect cross-component anomalies.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from typing import List, Dict, Any, Optional

try:
    from core.ledger_engine import VestigiaLedger, VestigiaEvent
except ImportError:
    from vestigia.core.ledger_engine import VestigiaLedger, VestigiaEvent


@dataclass
class CorrelatedTimeline:
    """A correlated timeline of events across components"""
    correlation_key: str  # session_id or agent_id
    events: List[Dict[str, Any]]
    total_events: int
    components_involved: List[str]
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Anomaly:
    """A detected cross-component anomaly"""
    anomaly_type: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    events_involved: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class EventCorrelator:
    """
    Cross-component event correlation for the Arto Security Suite.

    Correlates events by session ID or agent ID across Tessera (identity),
    VerityFlux (security), and Vestigia (audit) to build unified timelines
    and detect anomalies that span multiple components.
    """

    # Suspicious patterns that indicate cross-component anomalies
    ANOMALY_PATTERNS = {
        "rapid_token_after_threat": {
            "description": "Token issued shortly after threat detection",
            "severity": "high",
            "trigger_actions": ["TOKEN_ISSUED"],
            "preceding_actions": ["THREAT_DETECTED", "ACTION_BLOCKED"],
            "max_window_seconds": 60,
        },
        "delegation_after_drift": {
            "description": "Delegation created after session drift alert",
            "severity": "critical",
            "trigger_actions": ["DELEGATION_CREATED"],
            "preceding_actions": ["SESSION_DRIFT_ALERT"],
            "max_window_seconds": 120,
        },
        "manifest_fail_then_execution": {
            "description": "Tool executed after manifest verification failure",
            "severity": "critical",
            "trigger_actions": ["TOOL_EXECUTION"],
            "preceding_actions": ["TOOL_MANIFEST_FAILED"],
            "max_window_seconds": 30,
        },
    }

    def __init__(self, ledger: Optional[VestigiaLedger] = None):
        self.ledger = ledger

    def correlate_by_session(self, session_id: str) -> CorrelatedTimeline:
        """
        Correlate all events for a given session ID.

        Returns a unified timeline across all components.
        """
        events = self._query_events_by_field("session_id", session_id)
        return self._build_timeline(f"session:{session_id}", events)

    def correlate_by_agent(
        self, agent_id: str, time_window: Optional[timedelta] = None
    ) -> CorrelatedTimeline:
        """
        Correlate all events for a given agent within a time window.
        """
        if not self.ledger:
            return CorrelatedTimeline(
                correlation_key=f"agent:{agent_id}",
                events=[],
                total_events=0,
                components_involved=[],
            )

        start_date = None
        if time_window:
            start_date = datetime.now(UTC) - time_window

        raw_events = self.ledger.query_events(
            actor_id=agent_id,
            start_date=start_date,
            limit=500,
        )

        events = [e.to_dict() for e in raw_events]
        return self._build_timeline(f"agent:{agent_id}", events)

    def detect_cross_component_anomalies(
        self, timeline: CorrelatedTimeline
    ) -> List[Anomaly]:
        """
        Detect anomalies that span multiple components in a timeline.

        Looks for suspicious patterns like:
        - Token issued shortly after threat detection
        - Delegation created after drift alert
        - Tool executed after manifest verification failure
        """
        anomalies = []
        events = timeline.events

        for pattern_name, pattern in self.ANOMALY_PATTERNS.items():
            for i, event in enumerate(events):
                action = event.get("action_type", "")
                if action not in pattern["trigger_actions"]:
                    continue

                # Look backwards for preceding suspicious events
                event_time = self._parse_time(event.get("timestamp", ""))
                if not event_time:
                    continue

                for j in range(i - 1, max(i - 20, -1), -1):
                    prev = events[j]
                    prev_action = prev.get("action_type", "")
                    if prev_action not in pattern["preceding_actions"]:
                        continue

                    prev_time = self._parse_time(prev.get("timestamp", ""))
                    if not prev_time:
                        continue

                    delta = abs((event_time - prev_time).total_seconds())
                    if delta <= pattern["max_window_seconds"]:
                        anomalies.append(Anomaly(
                            anomaly_type=pattern_name,
                            description=pattern["description"],
                            severity=pattern["severity"],
                            events_involved=[
                                prev.get("event_id", ""),
                                event.get("event_id", ""),
                            ],
                        ))
                        break

        timeline.anomalies = [
            {
                "type": a.anomaly_type,
                "description": a.description,
                "severity": a.severity,
                "events": a.events_involved,
            }
            for a in anomalies
        ]

        return anomalies

    def _query_events_by_field(
        self, field_name: str, value: str
    ) -> List[Dict[str, Any]]:
        """Query events filtering by a specific evidence field."""
        if not self.ledger:
            return []

        all_events = self.ledger.query_events(limit=1000)
        matched = []
        for event in all_events:
            ev_dict = event.to_dict()
            evidence = ev_dict.get("evidence", {})
            if isinstance(evidence, dict):
                metadata = evidence.get("metadata", {})
                if metadata.get(field_name) == value:
                    matched.append(ev_dict)
            if ev_dict.get("actor_id", "").endswith(value):
                matched.append(ev_dict)

        return matched

    def _build_timeline(
        self, key: str, events: List[Dict[str, Any]]
    ) -> CorrelatedTimeline:
        """Build a correlated timeline from raw events."""
        components = set()
        for e in events:
            action = e.get("action_type", "")
            if action.startswith("TOKEN") or action.startswith("DELEGATION"):
                components.add("tessera")
            elif action.startswith("REASONING") or action.startswith("TOOL") or action.startswith("MEMORY"):
                components.add("verityflux")
            else:
                components.add("vestigia")

        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", ""))

        time_start = events[0].get("timestamp") if events else None
        time_end = events[-1].get("timestamp") if events else None

        timeline = CorrelatedTimeline(
            correlation_key=key,
            events=events,
            total_events=len(events),
            components_involved=list(components),
            time_range_start=time_start,
            time_range_end=time_end,
        )

        # Auto-detect anomalies
        self.detect_cross_component_anomalies(timeline)

        return timeline

    def _parse_time(self, ts: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None


__all__ = ["EventCorrelator", "CorrelatedTimeline", "Anomaly"]

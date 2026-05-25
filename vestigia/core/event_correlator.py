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
    governance_metrics: Dict[str, Any] = field(default_factory=dict)


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
        "protocol_alert_then_execution": {
            "description": "Tool executed shortly after protocol integrity alert",
            "severity": "critical",
            "trigger_actions": ["TOOL_EXECUTION"],
            "preceding_actions": ["PROTOCOL_INTEGRITY_ALERT"],
            "max_window_seconds": 45,
        },
        "reasoning_a2a_then_execution": {
            "description": "Tool executed shortly after A2A reasoning contamination alert",
            "severity": "critical",
            "trigger_actions": ["TOOL_EXECUTION"],
            "preceding_actions": ["REASONING_A2A_ALERT"],
            "max_window_seconds": 45,
        },
        "cross_agent_memory_then_execution": {
            "description": "Tool executed shortly after cross-agent memory poisoning alert",
            "severity": "critical",
            "trigger_actions": ["TOOL_EXECUTION"],
            "preceding_actions": ["MEMORY_CROSS_AGENT_ALERT"],
            "max_window_seconds": 45,
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
                contract_event = evidence.get("contract_event") or {}
                request = contract_event.get("request") or {}
                actor = contract_event.get("actor") or {}
                if request.get(field_name) == value or actor.get(field_name) == value:
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
            contract_event = _contract_event(e)
            source = str(contract_event.get("source") or "").lower()
            action = e.get("action_type", "")
            if source in {"tessera", "verityflux", "vestigia"}:
                components.add(source)
            elif action.startswith("TOKEN") or action.startswith("DELEGATION") or action.startswith("ACTION_VALIDATED"):
                components.add("tessera")
            elif (
                action.startswith("REASONING")
                or action.startswith("TOOL")
                or action.startswith("MEMORY")
                or action.startswith("PROTOCOL")
                or action == "ACTION_BLOCKED"
            ):
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
        timeline.governance_metrics = self._compute_governance_metrics(events, key)

        return timeline

    def _compute_governance_metrics(self, events: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
        first_seen_at = None
        detected_at = None
        decision_at = None
        intervened_at = None
        contained_at = None
        evidence_validated_at = None
        prevented_before_execution = False
        scoped_authority_enforced = False
        authority_enforceable = False
        intervention_success = False
        latest_decision = None
        identity_confidences: List[float] = []
        observed_identity_drift = False
        approval_coverage = False
        on_behalf_of_present = False
        delegation_depth_max = 0

        for event in events:
            ts = self._parse_time(event.get("timestamp", ""))
            if not ts:
                continue
            if first_seen_at is None:
                first_seen_at = ts

            contract_event = _contract_event(event)
            governance = contract_event.get("governance") if isinstance(contract_event, dict) else {}
            identity = contract_event.get("identity") if isinstance(contract_event, dict) else {}
            action = str(event.get("action_type") or "").upper()
            status = str(event.get("status") or "").upper()
            stage = str((governance or {}).get("stage") or _derive_stage(action, status)).lower()

            if stage == "detected" and detected_at is None:
                detected_at = ts
            elif stage == "decision" and decision_at is None:
                decision_at = ts
            elif stage == "intervened" and intervened_at is None:
                intervened_at = ts
            elif stage == "contained" and contained_at is None:
                contained_at = ts
            elif stage == "validated" and evidence_validated_at is None:
                evidence_validated_at = ts

            decision = (governance or {}).get("decision")
            if decision:
                latest_decision = str(decision)

            prevented_before_execution = prevented_before_execution or bool(
                (governance or {}).get("unsafe_action_prevented_before_execution")
            )
            scoped_authority_enforced = scoped_authority_enforced or bool(
                (governance or {}).get("scoped_authority_enforced")
            )
            authority_enforceable = authority_enforceable or bool(
                (governance or {}).get("authority_enforceable")
            )
            if isinstance(identity, dict):
                try:
                    if identity.get("identity_confidence") is not None:
                        identity_confidences.append(float(identity.get("identity_confidence")))
                except Exception:
                    pass
                observed_identity_drift = observed_identity_drift or bool(
                    identity.get("observed_identity_drift")
                )
                approval_coverage = approval_coverage or bool(
                    identity.get("approval_provenance") or identity.get("human_approver")
                )
                on_behalf_of_present = on_behalf_of_present or bool(identity.get("on_behalf_of"))
                try:
                    delegation_depth_max = max(
                        delegation_depth_max,
                        int(identity.get("delegation_depth") or 0),
                    )
                except Exception:
                    pass

        if contained_at is not None:
            intervention_success = True
        elif latest_decision in {"block", "deny", "revoke"}:
            intervention_success = True

        baseline = first_seen_at or detected_at
        return {
            "incident_key": key,
            "first_seen_at": _iso(first_seen_at),
            "detected_at": _iso(detected_at),
            "decision_at": _iso(decision_at),
            "intervened_at": _iso(intervened_at),
            "contained_at": _iso(contained_at),
            "evidence_validated_at": _iso(evidence_validated_at),
            "time_to_detection_seconds": _delta_seconds(baseline, detected_at),
            "time_to_decision_seconds": _delta_seconds(detected_at or baseline, decision_at),
            "time_to_containment_seconds": _delta_seconds(detected_at or baseline, contained_at),
            "time_to_evidence_validation_seconds": _delta_seconds(detected_at or baseline, evidence_validated_at),
            "intervention_success": intervention_success,
            "unsafe_action_prevented_before_execution": prevented_before_execution,
            "scoped_authority_enforced": scoped_authority_enforced,
            "authority_enforceable": authority_enforceable,
            "latest_decision": latest_decision,
            "identity_confidence_avg": round(sum(identity_confidences) / len(identity_confidences), 3) if identity_confidences else None,
            "observed_identity_drift": observed_identity_drift,
            "approval_provenance_present": approval_coverage,
            "on_behalf_of_present": on_behalf_of_present,
            "delegation_depth_max": delegation_depth_max,
        }

    def _parse_time(self, ts: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None


__all__ = ["EventCorrelator", "CorrelatedTimeline", "Anomaly"]


def _contract_event(event: Dict[str, Any]) -> Dict[str, Any]:
    evidence = event.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}
    contract_event = evidence.get("contract_event", {})
    return contract_event if isinstance(contract_event, dict) else {}


def _interoperability(event: Dict[str, Any]) -> Dict[str, Any]:
    contract_event = _contract_event(event)
    interoperability = contract_event.get("interoperability", {})
    return interoperability if isinstance(interoperability, dict) else {}


def _derive_stage(action: str, status: str) -> str:
    action = str(action or "").upper()
    status = str(status or "").upper()
    if action in {
        "REASONING_A2A_ALERT",
        "PROTOCOL_INTEGRITY_ALERT",
        "MEMORY_CROSS_AGENT_ALERT",
        "SESSION_DRIFT_ALERT",
        "THREAT_DETECTED",
    }:
        return "detected"
    if action in {"TOKEN_VALIDATED"}:
        return "decision"
    if action in {"ACTION_BLOCKED", "MEMORY_FILTERED"}:
        return "intervened"
    if action in {"TOKEN_REVOKED"} or status in {"BLOCKED", "DENY", "DENIED"}:
        return "contained"
    if action in {"ACTION_VALIDATED"}:
        return "validated"
    return "observed"


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _delta_seconds(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if not start or not end:
        return None
    return round((end - start).total_seconds(), 3)


def build_incident_timelines(events: List[Dict[str, Any]]) -> List[CorrelatedTimeline]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        contract_event = _contract_event(event)
        request = contract_event.get("request") if isinstance(contract_event, dict) else {}
        actor = contract_event.get("actor") if isinstance(contract_event, dict) else {}
        session_id = None
        if isinstance(request, dict):
            session_id = request.get("session_id") or request.get("trace_id")
        agent_id = actor.get("agent_id") if isinstance(actor, dict) else None
        key = session_id or f"agent:{agent_id or event.get('actor_id') or 'unknown'}"
        grouped.setdefault(str(key), []).append(event)

    correlator = EventCorrelator()
    timelines: List[CorrelatedTimeline] = []
    for key, grouped_events in grouped.items():
        timelines.append(correlator._build_timeline(key, grouped_events))
    timelines.sort(key=lambda item: item.time_range_end or "", reverse=True)
    return timelines


def summarize_governance_metrics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    timelines = build_incident_timelines(events)
    incidents = [
        timeline for timeline in timelines
        if timeline.governance_metrics.get("detected_at")
        or timeline.governance_metrics.get("decision_at")
        or timeline.governance_metrics.get("contained_at")
    ]

    def _avg(field: str) -> Optional[float]:
        values = [
            float(timeline.governance_metrics[field])
            for timeline in incidents
            if timeline.governance_metrics.get(field) is not None
        ]
        if not values:
            return None
        return round(sum(values) / len(values), 3)

    total = len(incidents)
    intervention_successes = sum(1 for t in incidents if t.governance_metrics.get("intervention_success"))
    prevented = sum(
        1 for t in incidents
        if t.governance_metrics.get("unsafe_action_prevented_before_execution")
    )
    scoped = sum(1 for t in incidents if t.governance_metrics.get("scoped_authority_enforced"))
    containments = sum(1 for t in incidents if t.governance_metrics.get("contained_at"))
    identity_confidences = [
        float(t.governance_metrics["identity_confidence_avg"])
        for t in incidents
        if t.governance_metrics.get("identity_confidence_avg") is not None
    ]
    drifted = sum(1 for t in incidents if t.governance_metrics.get("observed_identity_drift"))
    approval_backed = sum(1 for t in incidents if t.governance_metrics.get("approval_provenance_present"))
    on_behalf_of = sum(1 for t in incidents if t.governance_metrics.get("on_behalf_of_present"))
    delegation_depth_max = max(
        [int(t.governance_metrics.get("delegation_depth_max") or 0) for t in incidents],
        default=0,
    )

    return {
        "incidents_total": total,
        "time_to_detection_seconds_avg": _avg("time_to_detection_seconds"),
        "time_to_decision_seconds_avg": _avg("time_to_decision_seconds"),
        "time_to_containment_seconds_avg": _avg("time_to_containment_seconds"),
        "time_to_evidence_validation_seconds_avg": _avg("time_to_evidence_validation_seconds"),
        "intervention_success_rate": round((intervention_successes / total) * 100.0, 2) if total else None,
        "unsafe_action_prevented_before_execution_pct": round((prevented / total) * 100.0, 2) if total else None,
        "scoped_authority_coverage": round((scoped / total) * 100.0, 2) if total else None,
        "contained_incidents": containments,
        "identity_confidence_avg": round(sum(identity_confidences) / len(identity_confidences), 3) if identity_confidences else None,
        "observed_identity_drift_pct": round((drifted / total) * 100.0, 2) if total else None,
        "approval_provenance_coverage": round((approval_backed / total) * 100.0, 2) if total else None,
        "on_behalf_of_coverage": round((on_behalf_of / total) * 100.0, 2) if total else None,
        "delegation_depth_max": delegation_depth_max,
        "recent_timelines": [
            {
                "incident_key": timeline.correlation_key,
                "components_involved": timeline.components_involved,
                **timeline.governance_metrics,
            }
            for timeline in timelines[:20]
        ],
    }


def summarize_interoperability_report(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    timelines = build_incident_timelines(events)
    protocols: Dict[str, int] = {}
    standards: Dict[str, int] = {}
    framework_tags: Dict[str, int] = {}
    handoff_events = 0
    route_hops_max = 0
    missing_contract_id = 0
    recent_handoffs: List[Dict[str, Any]] = []

    for timeline in timelines:
        for event in timeline.events:
            interop = _interoperability(event)
            if not interop:
                continue
            protocol = str(interop.get("protocol") or "unknown")
            protocols[protocol] = protocols.get(protocol, 0) + 1
            for tag in interop.get("standards_tags", []) or []:
                standards[str(tag)] = standards.get(str(tag), 0) + 1
            for tag in interop.get("framework_tags", []) or []:
                framework_tags[str(tag)] = framework_tags.get(str(tag), 0) + 1
            hops = int(interop.get("route_hops") or len(interop.get("route") or []) or 0)
            route_hops_max = max(route_hops_max, hops)
            if not interop.get("contract_id"):
                missing_contract_id += 1
            if interop.get("handoff_from_agent_id") or interop.get("handoff_channel") or hops > 0:
                handoff_events += 1
                if len(recent_handoffs) < 25:
                    recent_handoffs.append({
                        "timestamp": event.get("timestamp"),
                        "incident_key": timeline.correlation_key,
                        "actor_id": event.get("actor_id"),
                        "action_type": event.get("action_type"),
                        "protocol": protocol,
                        "handoff_from_agent_id": interop.get("handoff_from_agent_id"),
                        "handoff_channel": interop.get("handoff_channel"),
                        "route_hops": hops,
                        "contract_id": interop.get("contract_id"),
                        "standards_tags": interop.get("standards_tags") or [],
                        "framework_tags": interop.get("framework_tags") or [],
                    })

    recent_handoffs.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return {
        "timelines_total": len(timelines),
        "protocol_counts": protocols,
        "standards_tag_counts": standards,
        "framework_tag_counts": framework_tags,
        "handoff_events": handoff_events,
        "route_hops_max": route_hops_max,
        "missing_contract_id_events": missing_contract_id,
        "recent_handoffs": recent_handoffs,
    }


__all__ = [
    "EventCorrelator",
    "CorrelatedTimeline",
    "Anomaly",
    "build_incident_timelines",
    "summarize_governance_metrics",
    "summarize_interoperability_report",
]

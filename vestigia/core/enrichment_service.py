#!/usr/bin/env python3
"""
Vestigia Enrichment Service - Bidirectional SIEM Sync
Phase 2: Production Hardening

Enriches events with contextual intelligence (GeoIP, threat IOCs,
historical actor patterns, risk scores) and handles inbound SIEM
webhooks for bidirectional correlation.
"""

import time
import logging
import threading
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Simple built-in GeoIP mapping (production would use maxminddb)
_GEOIP_SAMPLE: Dict[str, Dict[str, str]] = {
    "10.": {"country": "PRIVATE", "city": "Internal"},
    "192.168.": {"country": "PRIVATE", "city": "Internal"},
    "172.": {"country": "PRIVATE", "city": "Internal"},
}

# Configurable IOC list
_DEFAULT_IOCS: Dict[str, str] = {
    "evil.example.com": "Known C2 domain",
    "malware.test": "Malware distribution",
    "203.0.113.66": "Known scanner IP",
}


@dataclass
class EnrichmentResult:
    original_event: dict
    enrichments: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    ioc_matches: List[Dict[str, str]] = field(default_factory=list)


class EnrichmentService:
    """
    Bidirectional SIEM enrichment service.

    - Outbound: enriches Vestigia events before forwarding to SIEM
    - Inbound: handles SIEM webhook alerts and correlates with ledger events
    """

    def __init__(self, ledger=None, siem_config: Optional[dict] = None):
        self.ledger = ledger
        self.siem_config = siem_config or {}
        self.iocs: Dict[str, str] = dict(_DEFAULT_IOCS)
        self._actor_cache: Dict[str, List[dict]] = defaultdict(list)
        self._siem_alerts: List[dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = {"events_enriched": 0, "webhooks_processed": 0, "ioc_hits": 0}

    # ------------------------------------------------------------------
    # Event enrichment
    # ------------------------------------------------------------------

    def enrich_event(self, event: dict) -> dict:
        """Add contextual enrichment to an event dict."""
        enriched = dict(event)
        enrichments: Dict[str, Any] = {}

        # 1. GeoIP for IP addresses
        ip = self._extract_ip(event)
        if ip:
            enrichments["geo"] = self._geoip_lookup(ip)

        # 2. Threat intelligence / IOC matching
        ioc_hits = self._check_iocs(event)
        if ioc_hits:
            enrichments["ioc_matches"] = ioc_hits
            self._stats["ioc_hits"] += len(ioc_hits)

        # 3. Historical context for actor
        actor_id = event.get("actor_id")
        if actor_id:
            enrichments["actor_context"] = self._get_actor_context(actor_id)
            # Cache this event
            self._actor_cache[actor_id].append({
                "timestamp": event.get("timestamp", datetime.now(UTC).isoformat()),
                "action_type": event.get("action_type"),
                "status": event.get("status"),
            })
            # Keep cache bounded
            if len(self._actor_cache[actor_id]) > 1000:
                self._actor_cache[actor_id] = self._actor_cache[actor_id][-500:]

        # 4. Risk score
        risk = self.calculate_risk_score(actor_id) if actor_id else {"score": 0}
        enrichments["risk_score"] = risk["score"]
        enrichments["risk_factors"] = risk.get("factors", [])

        # Merge enrichments into evidence
        evidence = enriched.get("evidence", {})
        if isinstance(evidence, dict):
            evidence["enrichment"] = enrichments
        enriched["evidence"] = evidence

        self._stats["events_enriched"] += 1
        return enriched

    def calculate_risk_score(self, actor_id: str) -> dict:
        """Compute risk score for an actor based on recent behaviour."""
        history = self._actor_cache.get(actor_id, [])
        score = 0.0
        factors: List[str] = []

        if not history:
            return {"score": 0.0, "factors": ["no_history"]}

        recent = history[-100:]  # last 100 events

        # Factor 1: critical events in last 24h
        now = datetime.now(UTC)
        critical_24h = sum(
            1 for e in recent
            if e.get("status") in ("CRITICAL", "BLOCKED")
            and self._parse_ts(e.get("timestamp", "")) > now - timedelta(hours=24)
        )
        if critical_24h > 0:
            score += min(critical_24h * 15, 40)
            factors.append(f"{critical_24h}_critical_events_24h")

        # Factor 2: failure ratio
        failures = sum(1 for e in recent if e.get("status") in ("BLOCKED", "CRITICAL"))
        ratio = failures / len(recent) if recent else 0
        if ratio > 0.3:
            score += 25
            factors.append(f"high_failure_ratio_{ratio:.0%}")

        # Factor 3: off-hours activity
        off_hours = sum(
            1 for e in recent
            if self._is_off_hours(e.get("timestamp", ""))
        )
        if off_hours > len(recent) * 0.3:
            score += 15
            factors.append("significant_off_hours_activity")

        # Factor 4: high event volume
        if len(history) > 500:
            score += 10
            factors.append("high_event_volume")

        return {"score": min(score, 100.0), "factors": factors, "actor_id": actor_id}

    # ------------------------------------------------------------------
    # SIEM webhook handling
    # ------------------------------------------------------------------

    def handle_siem_webhook(self, payload: dict) -> dict:
        """Process an inbound SIEM alert and correlate with ledger events."""
        self._stats["webhooks_processed"] += 1
        self._siem_alerts.append(payload)

        source = payload.get("source", "unknown")
        alert_id = payload.get("alert_id", "")
        affected = payload.get("affected_events", [])

        # Correlate with ledger
        matched_events: List[dict] = []
        if self.ledger and affected:
            try:
                for eid in affected[:50]:
                    events = self.ledger.query_events(limit=1)
                    # Simple scan — production would use index
                    all_events = self.ledger.query_events(limit=10000)
                    for ev in all_events:
                        if getattr(ev, "event_id", None) == eid:
                            matched_events.append(ev.to_dict())
                            break
            except Exception as e:
                logger.warning("Correlation failed: %s", e)

        # Record enrichment event in ledger
        if self.ledger:
            try:
                self.ledger.append_event(
                    actor_id=f"siem:{source}",
                    action_type="SIEM_ALERT",
                    status="WARNING",
                    evidence={
                        "summary": f"SIEM alert from {source}: {payload.get('description', '')}",
                        "alert_id": alert_id,
                        "severity": payload.get("severity", "medium"),
                        "matched_events": len(matched_events),
                    },
                )
            except Exception as e:
                logger.warning("Failed to log SIEM alert: %s", e)

        return {
            "status": "processed",
            "alert_id": alert_id,
            "matched_events": len(matched_events),
            "events": matched_events[:10],
        }

    # ------------------------------------------------------------------
    # Event correlation
    # ------------------------------------------------------------------

    def correlate_events(
        self,
        trace_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        time_window: Optional[timedelta] = None,
    ) -> List[dict]:
        """Find related events by trace_id, actor_id, or time window."""
        if not self.ledger:
            return []

        try:
            events = self.ledger.query_events(
                actor_id=actor_id,
                limit=500,
            )
            results = [e.to_dict() for e in events]

            if trace_id:
                results = [
                    e for e in results
                    if e.get("evidence", {}).get("trace_id") == trace_id
                ]

            if time_window and results:
                cutoff = datetime.now(UTC) - time_window
                results = [
                    e for e in results
                    if self._parse_ts(e.get("timestamp", "")) >= cutoff
                ]

            return results
        except Exception as e:
            logger.warning("Correlation query failed: %s", e)
            return []

    # ------------------------------------------------------------------
    # Background processing
    # ------------------------------------------------------------------

    def start(self):
        """Start background enrichment worker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        logger.info("Enrichment service started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Enrichment service stopped")

    def _worker(self):
        while self._running:
            time.sleep(10)

    def get_stats(self) -> dict:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_ip(event: dict) -> Optional[str]:
        evidence = event.get("evidence", {})
        if isinstance(evidence, dict):
            for key in ("ip", "source_ip", "ip_address", "client_ip"):
                if key in evidence:
                    return evidence[key]
                meta = evidence.get("metadata", {})
                if isinstance(meta, dict) and key in meta:
                    return meta[key]
        return None

    @staticmethod
    def _geoip_lookup(ip: str) -> dict:
        for prefix, info in _GEOIP_SAMPLE.items():
            if ip.startswith(prefix):
                return {**info, "ip": ip}
        return {"country": "UNKNOWN", "city": "UNKNOWN", "ip": ip}

    def _check_iocs(self, event: dict) -> List[dict]:
        hits = []
        text = str(event)
        for indicator, description in self.iocs.items():
            if indicator in text:
                hits.append({"indicator": indicator, "description": description})
        return hits

    def _get_actor_context(self, actor_id: str) -> dict:
        history = self._actor_cache.get(actor_id, [])
        return {
            "previous_events": len(history),
            "last_seen": history[-1]["timestamp"] if history else None,
        }

    @staticmethod
    def _parse_ts(ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=UTC)

    @staticmethod
    def _is_off_hours(ts: str) -> bool:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.hour < 6 or dt.hour >= 22 or dt.weekday() >= 5
        except Exception:
            return False


if __name__ == "__main__":
    svc = EnrichmentService()
    sample = {
        "actor_id": "agent-007",
        "action_type": "TOOL_EXECUTION",
        "status": "SUCCESS",
        "evidence": {
            "summary": "Agent accessed evil.example.com",
            "metadata": {"ip": "192.168.1.42"},
        },
    }
    enriched = svc.enrich_event(sample)
    import json
    print(json.dumps(enriched, indent=2))
    print("\nRisk:", svc.calculate_risk_score("agent-007"))
    print("Stats:", svc.get_stats())

#!/usr/bin/env python3
"""
AIBOM Tracker - Persists AI Bill of Materials in Vestigia Ledger

Bridges SupplyChainMonitor (VerityFlux) with the Vestigia immutable
audit ledger, recording all component registrations and verifications.
"""

from typing import Dict, Any, Optional
from datetime import datetime, UTC

try:
    from core.ledger_engine import VestigiaLedger, ActionType, EventStatus, StructuredEvidence
except ImportError:
    from vestigia.core.ledger_engine import VestigiaLedger, ActionType, EventStatus, StructuredEvidence


class AIBOMTracker:
    """
    Persists AIBOM entries in the Vestigia immutable ledger.

    Records component registrations and verifications as ledger events
    for compliance and audit trail purposes.
    """

    def __init__(self, ledger: Optional[VestigiaLedger] = None):
        self.ledger = ledger

    def record_registration(
        self,
        component_id: str,
        component_type: str,
        version: str,
        provider: str,
        hash_value: str,
    ) -> Optional[str]:
        """Record an AIBOM component registration in the ledger."""
        if not self.ledger:
            return None

        event = self.ledger.append_event(
            actor_id=f"aibom:{provider}",
            action_type=ActionType.AIBOM_REGISTERED,
            status=EventStatus.SUCCESS,
            evidence=StructuredEvidence(
                summary=f"AIBOM component registered: {component_id} v{version}",
                metadata={
                    "component_id": component_id,
                    "component_type": component_type,
                    "version": version,
                    "provider": provider,
                    "hash": hash_value,
                },
            ),
        )
        return event.event_id

    def record_verification(
        self,
        component_id: str,
        verified: bool,
        reason: str,
    ) -> Optional[str]:
        """Record an AIBOM component verification in the ledger."""
        if not self.ledger:
            return None

        status = EventStatus.SUCCESS if verified else EventStatus.WARNING
        event = self.ledger.append_event(
            actor_id=f"aibom:verifier",
            action_type=ActionType.AIBOM_VERIFIED,
            status=status,
            evidence=StructuredEvidence(
                summary=f"AIBOM verification: {component_id} - {'PASS' if verified else 'FAIL'}",
                metadata={
                    "component_id": component_id,
                    "verified": verified,
                    "reason": reason,
                },
            ),
        )
        return event.event_id


__all__ = ["AIBOMTracker"]

#!/usr/bin/env python3
"""
Supply Chain Monitor - AI Bill of Materials (AIBOM) Tracking

Registers, verifies, and inventories all AI components (models, tools,
plugins) in the system. Generates AIBOM reports for compliance.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional


@dataclass
class AIBOMEntry:
    """Single component in the AI Bill of Materials"""
    component_id: str
    component_type: str  # "model", "tool", "plugin", "dataset"
    version: str
    hash: str
    provider: str
    registered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    verified: bool = False
    last_verified_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SupplyChainMonitor:
    """
    AI Supply Chain monitoring and AIBOM generation.

    Tracks all components in the AI system, verifies their integrity,
    and generates AIBOM (AI Bill of Materials) reports for compliance
    and audit purposes.
    """

    def __init__(self):
        self._components: Dict[str, AIBOMEntry] = {}

    def register_component(
        self,
        component_id: str,
        component_type: str,
        version: str,
        provider: str,
        hash_value: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AIBOMEntry:
        """
        Register a new component in the AIBOM.

        Args:
            component_id: Unique identifier for the component
            component_type: "model", "tool", "plugin", "dataset"
            version: Version string
            provider: Provider/vendor name
            hash_value: Integrity hash (auto-generated if not provided)
            metadata: Additional component metadata

        Returns:
            AIBOMEntry for the registered component
        """
        if not hash_value:
            hash_input = f"{component_id}:{component_type}:{version}:{provider}"
            hash_value = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        entry = AIBOMEntry(
            component_id=component_id,
            component_type=component_type,
            version=version,
            hash=hash_value,
            provider=provider,
            metadata=metadata or {},
        )

        self._components[component_id] = entry
        return entry

    def verify_component(self, component_id: str) -> Dict[str, Any]:
        """
        Verify a component's integrity against its registered hash.

        Returns:
            {"verified": bool, "component_id": str, "reason": str}
        """
        entry = self._components.get(component_id)
        if not entry:
            return {
                "verified": False,
                "component_id": component_id,
                "reason": "Component not registered",
            }

        # Recalculate hash
        hash_input = f"{entry.component_id}:{entry.component_type}:{entry.version}:{entry.provider}"
        expected_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        verified = expected_hash == entry.hash
        entry.verified = verified
        entry.last_verified_at = datetime.now(UTC).isoformat()

        return {
            "verified": verified,
            "component_id": component_id,
            "hash": entry.hash,
            "expected_hash": expected_hash,
            "reason": "Hash verified" if verified else "Hash mismatch - possible tampering",
        }

    def generate_aibom(self) -> Dict[str, Any]:
        """
        Generate a complete AI Bill of Materials report.

        Returns:
            AIBOM report with all components, verification status, and metadata
        """
        components = []
        for entry in self._components.values():
            components.append({
                "component_id": entry.component_id,
                "type": entry.component_type,
                "version": entry.version,
                "provider": entry.provider,
                "hash": entry.hash,
                "verified": entry.verified,
                "registered_at": entry.registered_at,
                "last_verified_at": entry.last_verified_at,
                "metadata": entry.metadata,
            })

        return {
            "aibom_version": "1.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "total_components": len(components),
            "verified_count": sum(1 for c in components if c["verified"]),
            "unverified_count": sum(1 for c in components if not c["verified"]),
            "by_type": self._count_by_type(),
            "components": components,
        }

    def get_component(self, component_id: str) -> Optional[AIBOMEntry]:
        return self._components.get(component_id)

    def list_components(self, component_type: Optional[str] = None) -> List[AIBOMEntry]:
        entries = list(self._components.values())
        if component_type:
            entries = [e for e in entries if e.component_type == component_type]
        return entries

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self._components.values():
            counts[entry.component_type] = counts.get(entry.component_type, 0) + 1
        return counts


__all__ = ["SupplyChainMonitor", "AIBOMEntry"]

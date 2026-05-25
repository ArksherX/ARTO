#!/usr/bin/env python3
"""
Local threat-card registry for tranche 9.

Normalizes public exploit patterns into a lightweight internal registry
without adding any continuous external ingestion.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ThreatCard:
    threat_id: str
    title: str
    incident_class: str
    severity: str
    summary: str
    attack_pattern: str
    mapped_action_types: List[str] = field(default_factory=list)
    mapped_event_types: List[str] = field(default_factory=list)
    taxonomy_tags: List[str] = field(default_factory=list)
    detection_surfaces: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    source_refs: List[str] = field(default_factory=list)
    publicity_points: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_THREAT_CARDS: List[ThreatCard] = [
    ThreatCard(
        threat_id="TC-001",
        title="Agent Identity Abuse",
        incident_class="agent_identity_abuse",
        severity="high",
        summary="Abuse of weak or drifted agent identity to obtain or exercise authority outside intended bounds.",
        attack_pattern="identity confusion -> unauthorized capability use -> policy bypass or silent misuse",
        mapped_action_types=["TOKEN_VALIDATED", "TOKEN_REVOKED", "ACTION_VALIDATED", "THREAT_DETECTED"],
        mapped_event_types=["token_validated", "token_revoked", "action_validated"],
        taxonomy_tags=["identity", "authorization", "delegation", "zero-trust"],
        detection_surfaces=["Tessera token validation", "Tessera action validation", "VerityFlux identity-aware enforcement", "Vestigia governance metrics"],
        mitigations=["scoped authority", "sender binding", "delegation narrowing", "identity confidence scoring", "revocation"],
        source_refs=["OWASP GenAI exploit round-up Q1 2026", "AI Identity: Standards, Gaps, and Research Directions for AI Agents"],
        publicity_points=["Identity is treated as a runtime enforcement problem, not just registration metadata.", "Observed-vs-declared identity confidence is preserved across the stack."],
    ),
    ThreatCard(
        threat_id="TC-002",
        title="Orchestration-Layer Exploitation",
        incident_class="orchestration_layer_exploitation",
        severity="critical",
        summary="Multi-step workflow manipulation that abuses reasoning, sequencing, or tool chaining rather than direct code execution.",
        attack_pattern="semantic manipulation -> tool-chain steering -> unsafe execution path",
        mapped_action_types=["REASONING_A2A_ALERT", "ACTION_BLOCKED", "MEMORY_CROSS_AGENT_ALERT", "SESSION_DRIFT_ALERT"],
        mapped_event_types=["REASONING_A2A_ALERT", "ACTION_BLOCKED", "MEMORY_CROSS_AGENT_ALERT"],
        taxonomy_tags=["orchestration", "reasoning", "workflow", "semantic-attack"],
        detection_surfaces=["VerityFlux reasoning interceptor", "VerityFlux session drift", "Vestigia incident timelines"],
        mitigations=["runtime policy enforcement", "reasoning interception", "memory filtering", "approval gates"],
        source_refs=["The Protocol That Trusts Everything", "OWASP GenAI exploit round-up Q1 2026"],
        publicity_points=["The suite constrains cognition-to-action transitions, not only prompts.", "Closed-loop metrics show whether the orchestration attack was contained before execution."],
    ),
    ThreatCard(
        threat_id="TC-003",
        title="MCP / Tool-Chain Abuse",
        incident_class="mcp_tool_chain_abuse",
        severity="critical",
        summary="Protocol, manifest, or tool-description abuse that turns interoperability into unsafe execution authority.",
        attack_pattern="malicious manifest/schema text -> unsafe parameter generation -> sensitive action",
        mapped_action_types=["PROTOCOL_INTEGRITY_ALERT", "TOOL_MANIFEST_FAILED", "ACTION_BLOCKED"],
        mapped_event_types=["PROTOCOL_INTEGRITY_ALERT"],
        taxonomy_tags=["mcp", "tool-chain", "protocol-integrity", "manifest"],
        detection_surfaces=["VerityFlux protocol integrity analyzer", "VerityFlux MCP identity guard", "Vestigia interoperability report"],
        mitigations=["signed manifests", "schema validation", "contract IDs", "route metadata", "pre-execution enforcement"],
        source_refs=["The Protocol That Trusts Everything", "OWASP MCP Top 10"],
        publicity_points=["MCP security is handled as a live trust and policy problem, not just static integration hygiene.", "Operators get protocol and handoff reporting, not opaque backend-only checks."],
    ),
    ThreatCard(
        threat_id="TC-004",
        title="Supply-Chain Compromise",
        incident_class="supply_chain_compromise",
        severity="high",
        summary="Previously trusted tools or servers drift into unsafe behavior through ecosystem or dependency compromise.",
        attack_pattern="trusted integration -> drift or rug pull -> hostile behavior under existing trust",
        mapped_action_types=["PROTOCOL_INTEGRITY_ALERT", "THREAT_DETECTED", "TOKEN_REVOKED"],
        mapped_event_types=["PROTOCOL_INTEGRITY_ALERT", "scan_completed"],
        taxonomy_tags=["supply-chain", "rug-pull", "trust-drift", "attestation"],
        detection_surfaces=["VerityFlux protocol analysis", "Tessera revocation", "Vestigia forensic history"],
        mitigations=["continuous trust validation", "attestation", "revocation", "evidence continuity"],
        source_refs=["The Protocol That Trusts Everything", "OWASP GenAI exploit round-up Q1 2026"],
        publicity_points=["Trust is modeled as revocable and behavior-dependent rather than permanent.", "The stack preserves evidence for post-trust-drift reconstruction."],
    ),
    ThreatCard(
        threat_id="TC-005",
        title="Destructive Autonomous Action",
        incident_class="destructive_autonomous_action",
        severity="critical",
        summary="An agent reaches a high-risk action path that could damage systems, data, or operations if not stopped pre-execution.",
        attack_pattern="unsafe reasoning or compromised context -> privileged tool path -> destructive action",
        mapped_action_types=["ACTION_BLOCKED", "TOKEN_REVOKED", "THREAT_DETECTED"],
        mapped_event_types=["ACTION_BLOCKED", "token_revoked"],
        taxonomy_tags=["destructive-action", "containment", "kill-chain", "blast-radius"],
        detection_surfaces=["VerityFlux tool interceptor", "Tessera revocation", "Vestigia governance metrics"],
        mitigations=["capability isolation", "runtime containment", "kill switch", "revocation", "human approval"],
        source_refs=["OWASP GenAI exploit round-up Q1 2026"],
        publicity_points=["The stack is built to contain the consequences of compromised reasoning before system damage occurs.", "Unsafe Action Prevented Before Execution is a first-class metric, not a side effect."],
    ),
]


def _registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "threat_cards.json"


def load_threat_cards() -> List[Dict[str, Any]]:
    path = _registry_path()
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [row for row in payload if isinstance(row, dict)]
        except Exception:
            pass
    return [card.to_dict() for card in DEFAULT_THREAT_CARDS]


def summarize_threat_card_coverage(
    events: List[Dict[str, Any]],
    cards: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    cards = cards or load_threat_cards()
    action_counts: Dict[str, int] = {}
    for event in events:
        action = str(event.get("action_type") or "").upper()
        if not action:
            continue
        action_counts[action] = action_counts.get(action, 0) + 1

    rows: List[Dict[str, Any]] = []
    covered = 0
    for card in cards:
        mapped_actions = [str(v).upper() for v in card.get("mapped_action_types", [])]
        matched_actions = [action for action in mapped_actions if action_counts.get(action)]
        observed_count = sum(action_counts.get(action, 0) for action in matched_actions)
        is_covered = observed_count > 0
        if is_covered:
            covered += 1
        rows.append({
            "threat_id": card.get("threat_id"),
            "title": card.get("title"),
            "incident_class": card.get("incident_class"),
            "severity": card.get("severity"),
            "coverage_status": "covered" if is_covered else "gap",
            "observed_count": observed_count,
            "matched_actions": matched_actions,
            "mapped_action_types": mapped_actions,
            "taxonomy_tags": card.get("taxonomy_tags", []),
            "detection_surfaces": card.get("detection_surfaces", []),
            "publicity_points": card.get("publicity_points", []),
        })

    return {
        "total_cards": len(cards),
        "covered_cards": covered,
        "coverage_pct": round((covered / len(cards)) * 100.0, 2) if cards else 0.0,
        "cards": rows,
    }

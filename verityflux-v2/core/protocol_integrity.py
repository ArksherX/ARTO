#!/usr/bin/env python3
"""
Structured protocol integrity analysis for A2A/MCP-style messages.

Focuses on operationally useful protocol-layer gaps:
- protocol mutation / schema drift
- field smuggling
- contract desynchronization
- multi-hop trust collapse
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, UTC
import hashlib
import json
import re
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE = {"low": 28.0, "medium": 56.0, "high": 78.0, "critical": 93.0}


@dataclass
class ProtocolIntegrityFinding:
    finding_id: str
    title: str
    severity: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolIntegrityAssessment:
    assessment_id: str
    protocol: str
    generated_at: str
    finding_count: int
    overall_severity: str
    overall_risk_score: float
    payload_hash: str
    findings: List[ProtocolIntegrityFinding]
    normalized_payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


class ProtocolIntegrityAnalyzer:
    SUSPICIOUS_FIELDS = {
        "bcc", "cc", "headers", "authorization", "api_key", "token",
        "system", "instructions", "instruction", "override", "debug",
        "raw", "raw_payload", "webhook", "callback_url", "forward_auth",
        "session_override", "agent_override", "tool_override",
    }
    ALIAS_GROUPS = [
        ("tool_name", "tool", "method", "action"),
        ("agent_id", "agent", "actor_id", "sender"),
        ("session_id", "sid", "session", "conversation_id"),
        ("schema_version", "version"),
        ("contract_id", "schema_id", "message_type"),
    ]

    def analyze(
        self,
        *,
        protocol: str,
        payload: Dict[str, Any],
        expected_contract: Optional[Dict[str, Any]] = None,
        route: Optional[List[Dict[str, Any]]] = None,
        identity_context: Optional[Dict[str, Any]] = None,
    ) -> ProtocolIntegrityAssessment:
        expected_contract = expected_contract or {}
        route = route or []
        identity_context = identity_context or {}
        findings: List[ProtocolIntegrityFinding] = []

        normalized_payload = self._normalize_payload(payload)
        payload_hash = self._stable_hash(normalized_payload)

        self._check_schema_drift(normalized_payload, expected_contract, findings)
        self._check_field_smuggling(normalized_payload, expected_contract, findings)
        self._check_contract_desync(normalized_payload, expected_contract, identity_context, findings)
        self._check_multi_hop_integrity(route, identity_context, findings)

        overall_severity = "low"
        if findings:
            overall_severity = max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

        overall_risk = SEVERITY_SCORE[overall_severity]
        if findings:
            overall_risk = min(96.0, overall_risk + max(0, len(findings) - 1) * 3.0)

        return ProtocolIntegrityAssessment(
            assessment_id=f"pi_{hashlib.sha1((payload_hash + protocol).encode('utf-8')).hexdigest()[:16]}",
            protocol=protocol,
            generated_at=datetime.now(UTC).isoformat(),
            finding_count=len(findings),
            overall_severity=overall_severity,
            overall_risk_score=round(overall_risk, 2),
            payload_hash=payload_hash,
            findings=findings,
            normalized_payload=normalized_payload,
        )

    def _check_schema_drift(
        self,
        payload: Dict[str, Any],
        expected_contract: Dict[str, Any],
        findings: List[ProtocolIntegrityFinding],
    ) -> None:
        evidence: List[str] = []
        required_top = set(expected_contract.get("required_top_fields", []))
        allowed_top = set(expected_contract.get("allowed_top_fields", []))
        required_args = set(expected_contract.get("required_argument_fields", []))
        allowed_args = set(expected_contract.get("allowed_argument_fields", []))
        expected_schema_version = expected_contract.get("schema_version")
        actual_schema_version = payload.get("schema_version") or payload.get("version")

        missing_top = sorted(f for f in required_top if f not in payload)
        if missing_top:
            evidence.append(f"missing top-level fields: {missing_top}")

        args = payload.get("arguments")
        if isinstance(args, dict):
            missing_args = sorted(f for f in required_args if f not in args)
            if missing_args:
                evidence.append(f"missing argument fields: {missing_args}")
            if allowed_args:
                unexpected_args = sorted(set(args.keys()) - allowed_args)
                if unexpected_args:
                    evidence.append(f"unexpected argument fields: {unexpected_args}")

        if allowed_top:
            unexpected_top = sorted(set(payload.keys()) - allowed_top)
            if unexpected_top:
                evidence.append(f"unexpected top-level fields: {unexpected_top}")

        if expected_schema_version and actual_schema_version and str(expected_schema_version) != str(actual_schema_version):
            evidence.append(
                f"schema version mismatch: expected {expected_schema_version}, got {actual_schema_version}"
            )

        expected_hash = expected_contract.get("expected_payload_hash")
        if expected_hash:
            actual_hash = self._stable_hash(payload)
            if actual_hash != expected_hash:
                evidence.append("payload hash differs from expected contract baseline")

        if evidence:
            findings.append(
                ProtocolIntegrityFinding(
                    finding_id="schema_drift",
                    title="Schema Drift / Protocol Mutation",
                    severity="high",
                    summary="Observed message shape diverges from the expected contract or schema baseline.",
                    evidence=evidence,
                    recommendations=[
                        "Pin schema versions and reject silent contract upgrades.",
                        "Enforce strict required-field and allowed-field checks on ingress.",
                        "Attach contract identifiers or hashes to inter-agent messages.",
                    ],
                )
            )

    def _check_field_smuggling(
        self,
        payload: Dict[str, Any],
        expected_contract: Dict[str, Any],
        findings: List[ProtocolIntegrityFinding],
    ) -> None:
        evidence: List[str] = []
        allowed_args = set(expected_contract.get("allowed_argument_fields", []))
        args = payload.get("arguments")
        if isinstance(args, dict):
            for key, value in args.items():
                lowered = str(key).strip().lower()
                if lowered in self.SUSPICIOUS_FIELDS:
                    evidence.append(f"suspicious argument field present: {key}")
                if allowed_args and key not in allowed_args:
                    evidence.append(f"argument field not declared in contract: {key}")
                if isinstance(value, str) and self._contains_hidden_json(value):
                    evidence.append(f"embedded structured payload inside string field: {key}")

        for path, value in self._flatten(payload).items():
            leaf = path.split(".")[-1].lower()
            if leaf in self.SUSPICIOUS_FIELDS and path not in {"arguments"}:
                evidence.append(f"suspicious nested field present: {path}")
            if isinstance(value, str) and re.search(r"\b(attacker|evil|bypass|override|ignore all)\b", value, re.I):
                evidence.append(f"suspicious value content at {path}")

        if evidence:
            findings.append(
                ProtocolIntegrityFinding(
                    finding_id="field_smuggling",
                    title="Field Smuggling",
                    severity="high",
                    summary="Message contains undeclared or suspicious fields that can bypass intended protocol semantics.",
                    evidence=sorted(set(evidence)),
                    recommendations=[
                        "Reject undeclared fields instead of ignoring them silently.",
                        "Normalize and inspect nested payloads before dispatch.",
                        "Block hidden override fields such as headers, bcc, callback_url, or embedded instruction payloads.",
                    ],
                )
            )

    def _check_contract_desync(
        self,
        payload: Dict[str, Any],
        expected_contract: Dict[str, Any],
        identity_context: Dict[str, Any],
        findings: List[ProtocolIntegrityFinding],
    ) -> None:
        evidence: List[str] = []
        bindings = expected_contract.get("bindings", {}) or {}
        observed = {
            "tool_name": payload.get("tool_name") or payload.get("tool"),
            "agent_id": payload.get("agent_id") or payload.get("agent") or payload.get("actor_id"),
            "session_id": payload.get("session_id") or payload.get("sid") or payload.get("session"),
        }
        for field_name, expected in bindings.items():
            actual = observed.get(field_name)
            if expected is not None and actual is not None and str(expected) != str(actual):
                evidence.append(f"{field_name} binding mismatch: expected {expected}, got {actual}")

        for group in self.ALIAS_GROUPS:
            values = {name: payload.get(name) for name in group if payload.get(name) is not None}
            unique = {str(v) for v in values.values()}
            if len(unique) > 1:
                evidence.append(f"alias disagreement for {group[0]}: {values}")

        if identity_context:
            if not identity_context.get("valid", True):
                evidence.append("identity context already marked invalid for this message")
            for field_name in ("agent_id", "tool_name", "session_id"):
                expected = identity_context.get(field_name)
                actual = observed.get(field_name)
                if expected and actual and str(expected) != str(actual):
                    evidence.append(f"identity context mismatch on {field_name}: expected {expected}, got {actual}")

        if evidence:
            findings.append(
                ProtocolIntegrityFinding(
                    finding_id="contract_desync",
                    title="Contract Desynchronization",
                    severity="critical" if any("identity context" in e for e in evidence) else "high",
                    summary="The message and the expected contract disagree about key bindings or semantic aliases.",
                    evidence=sorted(set(evidence)),
                    recommendations=[
                        "Bind agent, tool, and session identifiers into the message contract.",
                        "Disallow alias-based fallbacks when canonical fields disagree.",
                        "Reject messages whose runtime bindings diverge from identity context.",
                    ],
                )
            )

    def _check_multi_hop_integrity(
        self,
        route: List[Dict[str, Any]],
        identity_context: Dict[str, Any],
        findings: List[ProtocolIntegrityFinding],
    ) -> None:
        if not route:
            return

        evidence: List[str] = []
        if len(route) > 1 and not identity_context.get("has_sender_binding", False):
            evidence.append("multi-hop route present without sender-constrained binding")

        previous_schema = None
        previous_contract = None
        for idx, hop in enumerate(route, start=1):
            if not isinstance(hop, dict):
                evidence.append(f"route hop {idx} is not an object")
                continue
            if not hop.get("agent_id"):
                evidence.append(f"route hop {idx} missing agent_id")
            if not hop.get("authenticated", False):
                evidence.append(f"route hop {idx} not authenticated")
            if hop.get("signature_required", False) and not hop.get("signature_present", False):
                evidence.append(f"route hop {idx} missing required signature")

            schema_version = hop.get("schema_version")
            contract_id = hop.get("contract_id")
            if previous_schema and schema_version and str(previous_schema) != str(schema_version):
                evidence.append(
                    f"multi-hop schema drift between hops: {previous_schema} -> {schema_version}"
                )
            if previous_contract and contract_id and str(previous_contract) != str(contract_id):
                evidence.append(
                    f"multi-hop contract desync between hops: {previous_contract} -> {contract_id}"
                )
            previous_schema = schema_version or previous_schema
            previous_contract = contract_id or previous_contract

        if evidence:
            findings.append(
                ProtocolIntegrityFinding(
                    finding_id="trust_collapse",
                    title="Multi-Hop Trust Collapse",
                    severity="critical" if len(route) > 1 else "high",
                    summary="Route metadata indicates untrusted or inconsistently authenticated multi-hop message propagation.",
                    evidence=sorted(set(evidence)),
                    recommendations=[
                        "Require per-hop authentication and signature continuity for routed A2A messages.",
                        "Pin contract identifiers and schema versions across handoffs.",
                        "Treat unauthenticated or contract-mutated hops as protocol integrity failures, not soft warnings.",
                    ],
                )
            )

    def _normalize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {"raw_payload": str(payload)}
        return json.loads(json.dumps(payload, sort_keys=True, default=str))

    def _stable_hash(self, payload: Dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _flatten(self, data: Any, prefix: str = "") -> Dict[str, Any]:
        flat: Dict[str, Any] = {}
        if isinstance(data, dict):
            for key, value in data.items():
                child = f"{prefix}.{key}" if prefix else str(key)
                flat.update(self._flatten(value, child))
        elif isinstance(data, list):
            for idx, value in enumerate(data):
                child = f"{prefix}[{idx}]"
                flat.update(self._flatten(value, child))
        else:
            flat[prefix or "value"] = data
        return flat

    def _contains_hidden_json(self, text: str) -> bool:
        if len(text) < 8:
            return False
        if not ("{" in text and "}" in text and ":" in text):
            return False
        return any(token in text.lower() for token in ("tool_name", "agent_id", "session_id", "headers", "authorization"))


__all__ = [
    "ProtocolIntegrityFinding",
    "ProtocolIntegrityAssessment",
    "ProtocolIntegrityAnalyzer",
]

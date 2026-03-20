#!/usr/bin/env python3
"""
Generate an AIVSS-Agentic assessment report (Appendix A JSON schema).

Sources of truth:
- Vestigia ledger or shared audit log
- VerityFlux evaluation outputs (optional via observed_events.json)
- Tessera access decisions (via audit log or observed_events.json)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AIVSS_CATEGORIES = [
    "Agentic AI Tool Misuse",
    "Agent Access Control Violation",
    "Agent Cascading Failures",
    "Agent Orchestration & Multi-Agent Exploitation",
    "Agent Identity Impersonation",
    "Agent Memory & Context Manipulation",
    "Insecure Agent Critical Systems Interaction",
    "Agent Supply Chain & Dependency Risk",
    "Agent Untraceability",
    "Agent Goal & Instruction Manipulation",
]

DEFAULT_CVSS = {
    "Agentic AI Tool Misuse": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.5),
    "Agent Access Control Violation": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.0),
    "Agent Cascading Failures": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0),
    "Agent Orchestration & Multi-Agent Exploitation": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
    "Agent Identity Impersonation": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.2),
    "Agent Memory & Context Manipulation": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.8),
    "Insecure Agent Critical Systems Interaction": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.0),
    "Agent Supply Chain & Dependency Risk": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.0),
    "Agent Untraceability": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 6.5),
    "Agent Goal & Instruction Manipulation": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.0),
}


def _round_half_up(value: float, decimals: int = 1) -> float:
    factor = 10 ** decimals
    return math.floor(value * factor + 0.5) / factor


def _severity_band(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Low"


def _load_json_lines(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    events: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except PermissionError:
        return []
    return events


def _load_ledger(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, PermissionError):
        return []
    if isinstance(data, dict) and "events" in data:
        return data.get("events", [])
    if isinstance(data, list):
        return data
    return []


def _load_observed_events(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError:
        return {}


def _collect_evidence(
    audit_events: List[Dict[str, Any]],
    observed: Dict[str, Any],
) -> Dict[str, Any]:
    agent_ids = set()
    tools = set()
    approvals = 0
    tokens = 0
    delegations = 0
    policy_changes = 0
    memory_events = 0
    audit_events_seen = 0

    for event in audit_events:
        audit_events_seen += 1
        actor = event.get("actor_id") or event.get("agent_id")
        if actor:
            agent_ids.add(actor)
        action = (event.get("action_type") or "").upper()
        if "APPROVAL" in action or "HITL" in action:
            approvals += 1
        if "TOKEN" in action or "AGENT_REGISTERED" in action:
            tokens += 1
        if "DELEGATION" in action:
            delegations += 1
        if "POLICY" in action or "TOOL_REGISTRY" in action:
            policy_changes += 1
        if "MEMORY" in action or "CONTEXT" in action:
            memory_events += 1
        evidence = event.get("evidence") or {}
        if isinstance(evidence, dict):
            tool = evidence.get("tool") or evidence.get("action")
            if tool:
                tools.add(str(tool))

    agents_payload = observed.get("agents", {}) if isinstance(observed, dict) else {}
    for agent_id, payload in agents_payload.items():
        agent_ids.add(agent_id)
        if isinstance(payload, dict):
            for step in payload.get("steps", []):
                step_name = (step.get("step") or "").lower()
                if "token" in step_name or "register" in step_name:
                    tokens += 1
            for runtime_step in payload.get("runtime", []):
                action = (runtime_step.get("step") or "").lower()
                if "evaluate" in action or "access_validate" in action:
                    policy_changes += 1
            for scenario in payload.get("scenarios", []):
                action = (scenario.get("action") or "").lower()
                if "tool" in action or "exec" in action:
                    tools.add(action)

    return {
        "agent_count": len(agent_ids),
        "tool_count": len(tools),
        "approval_events": approvals,
        "token_events": tokens,
        "delegation_events": delegations,
        "policy_events": policy_changes,
        "memory_events": memory_events,
        "audit_events": audit_events_seen,
    }


def _score_factors(evidence: Dict[str, Any]) -> Dict[str, float]:
    agent_count = evidence.get("agent_count", 0)
    tool_count = evidence.get("tool_count", 0)
    approval_events = evidence.get("approval_events", 0)
    token_events = evidence.get("token_events", 0)
    delegation_events = evidence.get("delegation_events", 0)
    policy_events = evidence.get("policy_events", 0)
    memory_events = evidence.get("memory_events", 0)
    audit_events = evidence.get("audit_events", 0)

    autonomy = 0.5 if approval_events > 0 else 1.0
    tools = 1.0 if tool_count > 0 else 0.5
    language = 1.0  # LLM-driven natural language interface is assumed
    context = 1.0 if memory_events > 0 else 0.5
    non_determinism = 1.0  # LLM variability present in deployment
    opacity = 0.5 if audit_events > 0 else 1.0
    persistence = 1.0 if memory_events > 0 else 0.5
    identity = 1.0 if delegation_events > 0 else (0.5 if token_events > 0 else 0.0)
    multi_agent = 1.0 if agent_count > 1 else 0.0
    self_mod = 0.5 if policy_events > 0 else 0.0

    return {
        "autonomy": autonomy,
        "tools": tools,
        "language": language,
        "context": context,
        "non_determinism": non_determinism,
        "opacity": opacity,
        "persistence": persistence,
        "identity": identity,
        "multi_agent": multi_agent,
        "self_mod": self_mod,
    }


def _apply_scores(
    cvss_score: float,
    factors: Dict[str, float],
    threat_multiplier: float,
    mitigation_factor: float,
) -> Tuple[float, float, float, float, str]:
    factor_sum = sum(factors.values())
    risk_gap = 10.0 - cvss_score
    aars = risk_gap * (factor_sum / 10.0) * threat_multiplier
    aivss_raw = (cvss_score + aars) * mitigation_factor
    aivss = _round_half_up(aivss_raw, 1)
    return factor_sum, aars, mitigation_factor, aivss, _severity_band(aivss)


def _load_cvss_config(path: Optional[Path]) -> Dict[str, Tuple[str, float]]:
    if not path or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError:
        return {}
    output: Dict[str, Tuple[str, float]] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        vector = value.get("vector_string")
        score = value.get("score")
        if isinstance(vector, str) and isinstance(score, (int, float)):
            output[key] = (vector, float(score))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AIVSS-Agentic assessment report JSON.")
    parser.add_argument("--system-name", default="ML-Redteam Suite")
    parser.add_argument("--system-version", default="local")
    parser.add_argument("--assessor-id", default=os.getenv("USER", "assessor"))
    parser.add_argument("--assessment-date", default=dt.date.today().isoformat())
    parser.add_argument("--audit-log", default="shared_state/shared_audit.log")
    parser.add_argument("--ledger-path", default="vestigia/data/vestigia_ledger.json")
    parser.add_argument("--observed-events", default="")
    parser.add_argument("--sbom-path", default="")
    parser.add_argument("--cvss-config", default="")
    parser.add_argument("--threat-multiplier", type=float, default=0.97)
    parser.add_argument("--mitigation", choices=["none", "partial", "strong"], default="partial")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    audit_events = _load_json_lines(Path(args.audit_log))
    ledger_events = _load_ledger(Path(args.ledger_path))
    observed = _load_observed_events(Path(args.observed_events) if args.observed_events else None)

    combined_events = audit_events + ledger_events
    evidence = _collect_evidence(combined_events, observed)
    factors = _score_factors(evidence)

    mitigation_map = {"none": 1.0, "partial": 0.83, "strong": 0.67}
    mitigation_factor = mitigation_map[args.mitigation]

    cvss_overrides = _load_cvss_config(Path(args.cvss_config) if args.cvss_config else None)

    vulnerabilities: List[Dict[str, Any]] = []
    for idx, category in enumerate(AIVSS_CATEGORIES, start=1):
        vector, score = cvss_overrides.get(category, DEFAULT_CVSS[category])
        factor_sum, aars, mitigation_factor, aivss, severity = _apply_scores(
            cvss_score=score,
            factors=factors,
            threat_multiplier=args.threat_multiplier,
            mitigation_factor=mitigation_factor,
        )
        description = (
            f"Derived from suite evidence: agents={evidence['agent_count']}, "
            f"tools={evidence['tool_count']}, approvals={evidence['approval_events']}, "
            f"policy_events={evidence['policy_events']}, memory_events={evidence['memory_events']}."
        )
        if category == "Agent Supply Chain & Dependency Risk" and args.sbom_path:
            description += f" SBOM evidence: {args.sbom_path}."

        vulnerabilities.append(
            {
                "id": f"VULN-{idx:03d}",
                "title": category,
                "description": description,
                "owasp_category": category,
                "cvss_base": {"vector_string": vector, "score": score},
                "amplification_factors": factors,
                "threat_multiplier": args.threat_multiplier,
                "scores": {
                    "factor_sum": factor_sum,
                    "aars": aars,
                    "mitigation_factor": mitigation_factor,
                    "aivss": aivss,
                    "severity": severity,
                },
            }
        )

    notes = [
        "CVSS_Base values use default category baselines unless overridden via --cvss-config.",
        "Amplification factors are derived from observed audit evidence and suite telemetry.",
        f"Mitigation factor set to {mitigation_factor} ({args.mitigation}).",
    ]
    if args.sbom_path:
        notes.append(f"Supply chain evidence recorded at {args.sbom_path}.")

    report = {
        "metadata": {
            "system_name": args.system_name,
            "system_version": args.system_version,
            "assessment_date": args.assessment_date,
            "assessor_id": args.assessor_id,
            "notes": " ".join(notes),
        },
        "vulnerabilities": vulnerabilities,
    }

    output_path = Path(args.output) if args.output else Path("ops/evidence") / f"aivss_report_{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print(f"AIVSS report written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

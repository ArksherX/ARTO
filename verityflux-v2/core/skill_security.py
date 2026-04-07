#!/usr/bin/env python3
"""
Skill-layer security assessment for agentic skills and manifests.

This module scores a skill package against AST01-AST10 style risks using
format-aware parsing plus heuristic analysis of permissions, metadata, and
embedded behavior.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional, Tuple

import yaml


AST_RISK_META: Dict[str, Dict[str, str]] = {
    "AST01": {
        "title": "Malicious Skills",
        "severity": "critical",
        "summary": "Detects overtly malicious behavior, exfiltration patterns, and lethal-trifecta combinations.",
    },
    "AST02": {
        "title": "Supply Chain Compromise",
        "severity": "critical",
        "summary": "Checks provenance, signatures, pinning, and remote-install behaviors.",
    },
    "AST03": {
        "title": "Over-Privileged Skills",
        "severity": "high",
        "summary": "Flags excessive file, network, shell, and tool permissions.",
    },
    "AST04": {
        "title": "Insecure Metadata",
        "severity": "high",
        "summary": "Checks manifest completeness, schema hygiene, and publisher identity quality.",
    },
    "AST05": {
        "title": "Unsafe Deserialization",
        "severity": "high",
        "summary": "Detects unsafe YAML/JSON/pickle/eval loading paths and dangerous tags.",
    },
    "AST06": {
        "title": "Weak Isolation",
        "severity": "high",
        "summary": "Flags skills that assume host execution or bypass containment expectations.",
    },
    "AST07": {
        "title": "Update Drift",
        "severity": "medium",
        "summary": "Checks immutable versioning, changelog, and hash/pin discipline.",
    },
    "AST08": {
        "title": "Poor Scanning",
        "severity": "medium",
        "summary": "Checks whether the skill carries any machine-readable scanning/provenance markers.",
    },
    "AST09": {
        "title": "No Governance",
        "severity": "medium",
        "summary": "Checks owner, risk tier, approval, inventory, and audit-oriented metadata.",
    },
    "AST10": {
        "title": "Cross-Platform Reuse",
        "severity": "medium",
        "summary": "Flags multi-platform reuse without platform-specific constraints or validation.",
    },
}

AST_GAP_MATRIX: List[Dict[str, Any]] = [
    {
        "ast_id": "AST01",
        "title": "Malicious Skills",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux manifest and corpus heuristics for exfiltration, shell execution, and lethal-trifecta patterns",
            "Tessera least-privilege scopes and approval gates for risky activations",
            "Vestigia evidence continuity for assessment and activation events",
        ],
        "residual_gap": "Upstream registry malware reputation and transparency feeds remain external inputs.",
    },
    {
        "ast_id": "AST02",
        "title": "Supply Chain Compromise",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux signature, content-hash, publisher identity, and mutable-install pattern checks",
            "Tessera policy gating before activation",
            "Vestigia assessment trail for provenance decisions",
        ],
        "residual_gap": "Third-party registry transparency logs and publisher attestation roots are not hosted by this suite.",
    },
    {
        "ast_id": "AST03",
        "title": "Over-Privileged Skills",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux permission breadth analysis",
            "Tessera scope narrowing, runtime gating, and revocation",
            "Vestigia audit trail for grants and denials",
        ],
        "residual_gap": "None inside the suite beyond operator policy quality.",
    },
    {
        "ast_id": "AST04",
        "title": "Insecure Metadata",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux metadata completeness and impersonation heuristics across skill formats",
            "Tessera identity-linked approval flow for elevated skills",
        ],
        "residual_gap": "Formal external issuer verification still depends on upstream identity systems.",
    },
    {
        "ast_id": "AST05",
        "title": "Unsafe Deserialization",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux static pattern checks for unsafe loaders and dynamic execution",
            "Tessera containment policy mapping for execution-capable skills",
        ],
        "residual_gap": "Full code execution proving still depends on downstream sandbox execution environments.",
    },
    {
        "ast_id": "AST06",
        "title": "Weak Isolation",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux isolation expectation checks",
            "Tessera containment and sandbox attestation policies",
            "Vestigia evidence of isolation policy decisions",
        ],
        "residual_gap": "Host/container isolation is enforced by runtime infrastructure outside the suite process.",
    },
    {
        "ast_id": "AST07",
        "title": "Update Drift",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux version, hash, changelog, and mutable dependency checks",
            "Vestigia event history for reassessment decisions",
        ],
        "residual_gap": "Automated upstream update webhooks are not yet native.",
    },
    {
        "ast_id": "AST08",
        "title": "Poor Scanning",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux machine-readable scan metadata checks plus behavioral heuristics",
            "Vestigia evidence trail for repeated assessment results",
        ],
        "residual_gap": "Multi-scanner federation can be expanded if you want external scanner inputs merged automatically.",
    },
    {
        "ast_id": "AST09",
        "title": "No Governance",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux governance metadata checks",
            "Tessera approval and least-privilege workflows",
            "Vestigia audit and provenance retention",
        ],
        "residual_gap": "Governance quality still depends on operator-defined approval policy and ownership data.",
    },
    {
        "ast_id": "AST10",
        "title": "Cross-Platform Reuse",
        "assessment_coverage": "implemented",
        "suite_controls": [
            "VerityFlux cross-format parsing for SKILL.md, skill.json, manifest.json, and package.json",
            "Platform-specific constraint checks and per-platform review guidance",
        ],
        "residual_gap": "True universal manifest standardization remains an ecosystem-level problem outside the suite.",
    },
]


SEVERITY_SCORE = {
    "critical": 92.0,
    "high": 76.0,
    "medium": 58.0,
    "low": 30.0,
}


@dataclass
class SkillFinding:
    ast_id: str
    title: str
    severity: str
    risk_score: float
    summary: str
    evidence: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SkillAssessment:
    assessment_id: str
    name: str
    platform: str
    primary_filename: str
    generated_at: str
    normalized_manifest: Dict[str, Any]
    finding_count: int
    overall_risk_score: float
    overall_severity: str
    findings: List[SkillFinding]
    mapped_controls: Dict[str, List[str]]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data


class SkillSecurityAssessor:
    """Assess skill manifests/packages against AST01-AST10 heuristics."""

    def assess(
        self,
        *,
        name: str,
        content: str,
        primary_filename: str = "skill.txt",
        platform: Optional[str] = None,
        supporting_files: Optional[Dict[str, str]] = None,
    ) -> SkillAssessment:
        supporting_files = supporting_files or {}
        manifest, detected_platform = self._parse_manifest(
            content=content,
            primary_filename=primary_filename,
            platform_hint=platform,
        )
        merged_text = self._merge_corpus(content, supporting_files)
        findings = self._evaluate_findings(
            manifest=manifest,
            corpus=merged_text,
            primary_filename=primary_filename,
            supporting_files=supporting_files,
            platform=(platform or detected_platform or "generic"),
        )
        overall_score, overall_severity = self._overall(findings)
        mapped_controls = self._mapped_controls(findings)
        return SkillAssessment(
            assessment_id=f"skill_{uuid.uuid4().hex}",
            name=name,
            platform=(platform or detected_platform or "generic"),
            primary_filename=primary_filename,
            generated_at=datetime.now(UTC).isoformat(),
            normalized_manifest=manifest,
            finding_count=len(findings),
            overall_risk_score=overall_score,
            overall_severity=overall_severity,
            findings=findings,
            mapped_controls=mapped_controls,
        )

    def gap_matrix(self) -> List[Dict[str, Any]]:
        """Return suite coverage status for AST01-AST10."""
        return [dict(row) for row in AST_GAP_MATRIX]

    def _parse_manifest(
        self,
        *,
        content: str,
        primary_filename: str,
        platform_hint: Optional[str],
    ) -> Tuple[Dict[str, Any], str]:
        filename = (primary_filename or "").lower()
        manifest: Dict[str, Any] = {}
        detected = (platform_hint or "").lower()

        if filename.endswith(".json") or content.lstrip().startswith("{"):
            try:
                manifest = json.loads(content)
            except json.JSONDecodeError:
                manifest = {"raw_content": content}
            if filename == "package.json":
                detected = detected or "vscode"
            elif filename == "manifest.json":
                detected = detected or "cursor_codex"
            elif filename == "skill.json":
                detected = detected or "claude_code"
        elif filename.endswith(".md") or content.lstrip().startswith("---"):
            frontmatter, body = self._extract_frontmatter(content)
            manifest = frontmatter or {}
            if body:
                manifest.setdefault("body", body)
            if filename == "skill.md":
                detected = detected or "openclaw"
        else:
            manifest = {"raw_content": content}

        manifest.setdefault("name", self._first_str(manifest, ["name", "title"]) or "unnamed-skill")
        manifest.setdefault("description", self._first_str(manifest, ["description", "summary"]) or "")
        manifest.setdefault("version", self._first_str(manifest, ["version"]) or "")
        manifest.setdefault("author", self._normalize_author(manifest))
        manifest.setdefault("platforms", self._normalize_platforms(manifest, detected))
        manifest.setdefault("permissions", self._normalize_permissions(manifest))
        manifest.setdefault("scan_status", manifest.get("scan_status") or {})
        manifest.setdefault("signature", self._first_str(manifest, ["signature"]) or "")
        manifest.setdefault("content_hash", self._first_str(manifest, ["content_hash"]) or "")
        manifest.setdefault("risk_tier", self._first_str(manifest, ["risk_tier"]) or "")
        manifest.setdefault("changelog", manifest.get("changelog") or [])
        return manifest, detected or "generic"

    def _extract_frontmatter(self, content: str) -> Tuple[Dict[str, Any], str]:
        stripped = content.lstrip()
        if not stripped.startswith("---"):
            return {}, content
        lines = stripped.splitlines()
        if not lines or lines[0].strip() != "---":
            return {}, content
        try:
            end_index = next(i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---")
        except StopIteration:
            return {}, content
        frontmatter_text = "\n".join(lines[1:end_index])
        body = "\n".join(lines[end_index + 1:])
        try:
            parsed = yaml.safe_load(frontmatter_text) or {}
            if not isinstance(parsed, dict):
                parsed = {"frontmatter": parsed}
            return parsed, body
        except Exception:
            return {"frontmatter_raw": frontmatter_text}, body

    def _merge_corpus(self, content: str, supporting_files: Dict[str, str]) -> str:
        parts = [content]
        for filename, body in sorted(supporting_files.items()):
            parts.append(f"\n# file:{filename}\n{body}")
        return "\n".join(parts)

    def _normalize_author(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        author = manifest.get("author")
        if isinstance(author, dict):
            return author
        if isinstance(author, str):
            return {"name": author}
        publisher = manifest.get("publisher")
        if isinstance(publisher, str):
            return {"name": publisher}
        return {}

    def _normalize_platforms(self, manifest: Dict[str, Any], detected: str) -> List[str]:
        platforms = manifest.get("platforms")
        if isinstance(platforms, list):
            return [str(item).strip() for item in platforms if str(item).strip()]
        if isinstance(platforms, str):
            return [platforms]
        if detected:
            return [detected]
        return []

    def _normalize_permissions(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        permissions = manifest.get("permissions")
        if isinstance(permissions, dict):
            return permissions

        normalized: Dict[str, Any] = {}
        for key in ("tools", "requires", "activationEvents", "scripts", "hooks"):
            if key in manifest:
                normalized[key] = manifest[key]
        return normalized

    def _first_str(self, manifest: Dict[str, Any], keys: List[str]) -> str:
        for key in keys:
            value = manifest.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _evaluate_findings(
        self,
        *,
        manifest: Dict[str, Any],
        corpus: str,
        primary_filename: str,
        supporting_files: Dict[str, str],
        platform: str,
    ) -> List[SkillFinding]:
        findings: List[SkillFinding] = []
        checks = [
            self._check_ast01,
            self._check_ast02,
            self._check_ast03,
            self._check_ast04,
            self._check_ast05,
            self._check_ast06,
            self._check_ast07,
            self._check_ast08,
            self._check_ast09,
            self._check_ast10,
        ]
        for check in checks:
            finding = check(manifest, corpus, primary_filename, supporting_files, platform)
            if finding:
                findings.append(finding)
        findings.sort(key=lambda item: item.risk_score, reverse=True)
        return findings

    def _make_finding(self, ast_id: str, summary: str, evidence: List[str], recommendations: List[str], score_boost: float = 0.0) -> SkillFinding:
        meta = AST_RISK_META[ast_id]
        base = SEVERITY_SCORE[meta["severity"]]
        risk_score = round(min(100.0, base + score_boost), 2)
        return SkillFinding(
            ast_id=ast_id,
            title=meta["title"],
            severity=meta["severity"],
            risk_score=risk_score,
            summary=summary,
            evidence=evidence,
            recommendations=recommendations,
        )

    def _has_any(self, corpus: str, patterns: List[str]) -> List[str]:
        lowered = corpus.lower()
        hits = []
        for pattern in patterns:
            if pattern.lower() in lowered:
                hits.append(pattern)
        return hits

    def _permission_strings(self, manifest: Dict[str, Any]) -> str:
        return json.dumps(manifest.get("permissions", {}), sort_keys=True).lower()

    def _check_ast01(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        exfil = self._has_any(corpus, ["curl ", "wget ", "webhook", "requests.post", "fetch(", "http://", "https://"])
        secrets = self._has_any(corpus, ["~/.ssh", ".env", "api_key", "wallet", "private key", "browser data", "memory.md", "soul.md"])
        execution = self._has_any(corpus, ["bash -c", "sh -c", "os.system", "subprocess", "shell: true", "powershell", "exec("])
        if not (exfil and secrets and execution):
            suspicious = self._has_any(corpus, ["base64", "nc -e", "chmod +x", "rm -rf", "exfil", "token exfiltration"])
            if not suspicious:
                return None
            return self._make_finding(
                "AST01",
                "Skill includes suspicious execution or exfiltration patterns consistent with malicious behavior.",
                suspicious[:6],
                [
                    "Block installation or activation until manual review completes.",
                    "Require package signing and behavior review before trust is granted.",
                    "Constrain execution with Tessera policy and VerityFlux runtime containment.",
                ],
                score_boost=4.0,
            )
        evidence = list(dict.fromkeys((exfil + secrets + execution)))[:8]
        return self._make_finding(
            "AST01",
            "Skill satisfies a lethal-trifecta profile: private data access, external communication, and active execution.",
            evidence,
            [
                "Quarantine this skill until provenance and intent are validated.",
                "Strip shell or external egress permissions and require explicit approval.",
                "Record activation attempts through Vestigia and require Tessera-issued least-privilege scopes.",
            ],
            score_boost=8.0,
        )

    def _check_ast02(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        missing = []
        if not manifest.get("signature"):
            missing.append("signature missing")
        if not manifest.get("content_hash"):
            missing.append("content_hash missing")
        author = manifest.get("author") or {}
        if not isinstance(author, dict) or not author.get("identity"):
            missing.append("publisher identity missing")
        remote_install = self._has_any(corpus, ["curl | sh", "wget | bash", "npm install latest", "pip install -U", "git clone http"])
        if not missing and not remote_install:
            return None
        evidence = missing + remote_install[:4]
        return self._make_finding(
            "AST02",
            "Skill lacks provenance controls or references mutable remote-install patterns, increasing supply-chain risk.",
            evidence,
            [
                "Require signature, content hash, and publisher identity before activation.",
                "Pin remote dependencies to immutable hashes or versions.",
                "Treat the package as untrusted until verified by VerityFlux skill assessment and operator approval.",
            ],
            score_boost=6.0,
        )

    def _check_ast03(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        perms = self._permission_strings(manifest)
        broad = self._has_any(perms, ['"*"', "deny: \"*\"", "shell", "execute", "write", "~/.ssh", ".env", "memory.md", "soul.md"])
        tool_count = 0
        tools = manifest.get("permissions", {}).get("tools") if isinstance(manifest.get("permissions"), dict) else None
        if isinstance(tools, list):
            tool_count = len(tools)
        if not broad and tool_count <= 4:
            return None
        evidence = broad[:6]
        if tool_count > 4:
            evidence.append(f"declares {tool_count} tools")
        return self._make_finding(
            "AST03",
            "Skill requests broader privileges than are typical for a narrowly-scoped behavior package.",
            evidence,
            [
                "Reduce file, network, shell, and tool permissions to the minimum required set.",
                "Enforce Tessera least-privilege scopes before the skill can execute.",
                "Add VerityFlux policy checks for dangerous path, shell, and egress combinations.",
            ],
            score_boost=5.0,
        )

    def _check_ast04(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        missing = []
        for field in ("name", "description", "version"):
            if not manifest.get(field):
                missing.append(f"{field} missing")
        author = manifest.get("author") or {}
        if not isinstance(author, dict) or not author.get("name"):
            missing.append("author missing")
        impersonation = self._has_any(corpus, ["google", "microsoft", "openai", "anthropic"])
        if not missing and len(impersonation) < 2:
            return None
        evidence = missing + impersonation[:3]
        return self._make_finding(
            "AST04",
            "Manifest metadata is incomplete or could mislead operators about publisher identity and intent.",
            evidence,
            [
                "Require complete metadata, publisher identity, and consistent manifest schema before acceptance.",
                "Reject branded or publisher-sensitive claims unless backed by verifiable identity.",
                "Add schema validation to CI and pre-install checks.",
            ],
            score_boost=3.0,
        )

    def _check_ast05(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        hits = self._has_any(
            corpus,
            [
                "yaml.load(",
                "pickle.loads",
                "marshal.loads",
                "eval(",
                "exec(",
                "!!python/object",
                "unsafe_load",
                "__import__(",
            ],
        )
        if not hits:
            return None
        return self._make_finding(
            "AST05",
            "Skill package or handlers include unsafe deserialization or dynamic execution constructs.",
            hits[:6],
            [
                "Use safe YAML/JSON loaders only.",
                "Remove dynamic execution and deserialize untrusted data inside a sandboxed parser boundary.",
                "Require code review before enabling the skill.",
            ],
            score_boost=5.0,
        )

    def _check_ast06(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        hits = self._has_any(corpus, ["docker", "sandbox", "container", "shell: true", "host mode", "process isolation"])
        perms = self._permission_strings(manifest)
        risky = self._has_any(perms, ["shell", "~/.ssh", "/etc/", "memory.md", "soul.md"])
        isolated = any(token in " ".join(hits).lower() for token in ("sandbox", "container", "isolation"))
        if risky and not isolated:
            return self._make_finding(
                "AST06",
                "Skill assumes privileged host execution without declaring meaningful isolation controls.",
                risky[:6],
                [
                    "Run the skill inside a container or sandbox boundary by default.",
                    "Require sandbox attestation before execution-capable paths are allowed.",
                    "Prevent direct writes to identity or memory files unless explicitly justified.",
                ],
                score_boost=4.0,
            )
        return None

    def _check_ast07(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        evidence = []
        version = manifest.get("version", "")
        if not version:
            evidence.append("version missing")
        if not manifest.get("content_hash"):
            evidence.append("content hash missing")
        if not manifest.get("changelog"):
            evidence.append("changelog missing")
        evidence.extend(self._has_any(corpus, ["latest", "^", "~", ">= ", "unbounded"]))
        if not evidence:
            return None
        return self._make_finding(
            "AST07",
            "Skill update controls are weak, making drift and silent behavior changes harder to detect.",
            evidence[:6],
            [
                "Pin dependencies and versions immutably.",
                "Attach content hashes and changelog entries to every update.",
                "Re-assess the skill whenever version or hash changes.",
            ],
            score_boost=2.0,
        )

    def _check_ast08(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        scan_status = manifest.get("scan_status") or {}
        evidence = []
        if not scan_status:
            evidence.append("scan_status missing")
        else:
            if not scan_status.get("scanner"):
                evidence.append("scanner missing")
            if not scan_status.get("last_scanned"):
                evidence.append("last_scanned missing")
            if not scan_status.get("result"):
                evidence.append("scan result missing")
        if not evidence:
            return None
        return self._make_finding(
            "AST08",
            "Skill does not carry machine-readable scanning metadata, making trust decisions weaker and less repeatable.",
            evidence,
            [
                "Record scanner name, scan date, and result inside the skill metadata.",
                "Use both metadata validation and behavioral assessment before installation.",
                "Treat unscanned skills as higher-risk during approval.",
            ],
            score_boost=1.0,
        )

    def _check_ast09(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        evidence = []
        if not manifest.get("risk_tier"):
            evidence.append("risk_tier missing")
        author = manifest.get("author") or {}
        if not isinstance(author, dict) or not author.get("name"):
            evidence.append("owner missing")
        if "approval" not in corpus.lower():
            evidence.append("approval workflow not declared")
        if "audit" not in corpus.lower() and "log" not in corpus.lower():
            evidence.append("audit/logging intent not declared")
        if not evidence:
            return None
        return self._make_finding(
            "AST09",
            "Governance metadata is incomplete, making inventory, approval, and audit workflows weaker.",
            evidence[:6],
            [
                "Add owner, risk tier, approval path, and audit expectations to the manifest.",
                "Require Tessera approval workflows for elevated risk tiers.",
                "Record all activation and policy decisions in Vestigia.",
            ],
            score_boost=1.0,
        )

    def _check_ast10(self, manifest: Dict[str, Any], corpus: str, *_args) -> Optional[SkillFinding]:
        platforms = manifest.get("platforms") or []
        if not isinstance(platforms, list):
            platforms = [str(platforms)]
        platform_count = len([p for p in platforms if p])
        evidence = []
        if platform_count > 1:
            evidence.append(f"declares {platform_count} platforms")
            if "platform_constraints" not in corpus.lower() and "platform_overrides" not in corpus.lower():
                evidence.append("no platform-specific constraints")
        if platform_count <= 1:
            return None
        return self._make_finding(
            "AST10",
            "Skill is designed for reuse across multiple agent platforms without explicit platform-specific validation controls.",
            evidence,
            [
                "Define platform-specific permission and execution constraints.",
                "Validate the manifest separately for each supported platform.",
                "Do not assume one manifest is safe across all runtimes without per-platform review.",
            ],
            score_boost=2.0,
        )

    def _overall(self, findings: List[SkillFinding]) -> Tuple[float, str]:
        if not findings:
            return 0.0, "low"
        max_score = max(item.risk_score for item in findings)
        score = min(100.0, round(max_score + max(0, len(findings) - 1) * 2.5, 2))
        if score >= 90:
            severity = "critical"
        elif score >= 70:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        else:
            severity = "low"
        return score, severity

    def _mapped_controls(self, findings: List[SkillFinding]) -> Dict[str, List[str]]:
        controls = {"tessera": [], "verityflux": [], "vestigia": []}
        for finding in findings:
            if finding.ast_id in {"AST01", "AST02", "AST03", "AST06", "AST09"}:
                controls["tessera"].append("least-privilege scopes / approval / revocation")
            if finding.ast_id in {"AST01", "AST02", "AST03", "AST04", "AST05", "AST07", "AST08", "AST10"}:
                controls["verityflux"].append("manifest validation / behavior scoring / policy gating")
            if finding.ast_id in {"AST01", "AST02", "AST08", "AST09"}:
                controls["vestigia"].append("evidence continuity / audit / provenance trail")
        return {key: sorted(set(values)) for key, values in controls.items() if values}


__all__ = [
    "SkillSecurityAssessor",
    "SkillAssessment",
    "SkillFinding",
    "AST_RISK_META",
    "AST_GAP_MATRIX",
]

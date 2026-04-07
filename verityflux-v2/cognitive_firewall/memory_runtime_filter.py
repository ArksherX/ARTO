#!/usr/bin/env python3
"""
Memory Runtime Filter - RAG Retrieval Sanitization at Runtime

Wraps MemorySanitizer and InputValidator to filter RAG retrievals
before they reach the agent. Strips/redacts poisoned segments rather
than blocking entire documents. Treats all retrievals as untrusted input.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, UTC

from .memory_sanitizer import MemorySanitizer
from .input_validator import InputValidator


@dataclass
class FilterResult:
    """Result of filtering memory/RAG retrievals"""
    cleaned_retrievals: List[Dict[str, Any]]
    removed_count: int
    modified_count: int
    threats_found: List[str]
    audit_trail: List[Dict[str, Any]]
    cross_agent_findings: List[Dict[str, Any]] = field(default_factory=list)
    cross_agent_alert: bool = False
    risk_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class MemoryRuntimeFilter:
    """
    Runtime filter for RAG/memory retrievals.

    All RAG retrievals are treated as untrusted input. Poisoned segments
    are stripped or redacted rather than blocking entire documents,
    preserving useful content while neutralizing threats.
    """

    # Patterns to strip from retrievals (instruction injection)
    STRIP_PATTERNS = [
        r'\[HIDDEN:[^\]]*\]',
        r'\[SYSTEM:[^\]]*\]',
        r'<!--\s*system:.*?-->',
        r'<instruction>.*?</instruction>',
        r'system prompt:.*?(?:\n|$)',
        r'ignore previous.*?(?:\n|$)',
        r'new instructions:.*?(?:\n|$)',
        r'you are now.*?(?:\n|$)',
        r'disregard.*?(?:\n|$)',
        r'override:.*?(?:\n|$)',
        r'user has authorized.*?(?:\n|$)',
    ]

    # Credential patterns to redact
    CREDENTIAL_PATTERNS = [
        (r'(api[_-]?key\s*[:=]\s*["\']?)[\w-]{20,}', r'\1[REDACTED]'),
        (r'(api[_-]?key\s*[:=]\s*["\']?)[^\s,"\']+', r'\1[REDACTED]'),
        (r'(password\s*[:=]\s*["\']?)[\w!@#$%^&*]{8,}', r'\1[REDACTED]'),
        (r'(db[_-]?password\s*[:=]\s*["\']?)[^\s,"\']+', r'\1[REDACTED]'),
        (r'(token\s*[:=]\s*["\']?)[\w.-]{20,}', r'\1[REDACTED]'),
        (r'(secret\s*[:=]\s*["\']?)[\w-]{20,}', r'\1[REDACTED]'),
    ]

    CROSS_AGENT_SUSPICION_PATTERNS = [
        r'previous session',
        r'shared team memory',
        r'colleague',
        r'authorized by (?:the )?platform admin',
        r'disable(?:d)? (?:all )?safety',
        r'bypass all content restrictions',
        r'full admin access',
        r'developer mode',
        r'policy id:',
        r'trust this user',
    ]

    def __init__(self, adversarial_scorer=None):
        self.sanitizer = MemorySanitizer()
        self.adversarial_scorer = adversarial_scorer
        self._filtered_count = 0
        self._total_count = 0

    def filter_retrievals(
        self,
        retrievals: List[Dict[str, Any]],
        agent_context: Optional[Dict[str, Any]] = None,
    ) -> FilterResult:
        """
        Filter a batch of RAG retrievals.

        Args:
            retrievals: List of {"content": str, "id": str, ...}
            agent_context: Optional context about the requesting agent

        Returns:
            FilterResult with cleaned retrievals and audit trail
        """
        cleaned = []
        removed_count = 0
        modified_count = 0
        threats_found = []
        audit_trail = []
        cross_agent_findings = []

        for retrieval in retrievals:
            self._total_count += 1
            content = retrieval.get("content", "")
            source_id = retrieval.get("id", f"doc_{self._total_count}")

            cleaned_text, was_modified = self.filter_single(content, source_id)

            # Run adversarial scoring if available
            adversarial_flag = False
            if self.adversarial_scorer and cleaned_text:
                try:
                    score_result = self.adversarial_scorer.score_input(
                        cleaned_text, context=agent_context or {}
                    )
                    if score_result.is_adversarial:
                        adversarial_flag = True
                        threats_found.append(
                            f"Adversarial content in {source_id}: "
                            f"{score_result.intent_class} ({score_result.hostility_score:.2f})"
                        )
                except Exception:
                    pass

            # If content is entirely poisoned or adversarial, remove it
            if not cleaned_text.strip() or adversarial_flag:
                removed_count += 1
                self._filtered_count += 1
                cross_agent_finding = self._analyze_cross_agent_poisoning(
                    retrieval=retrieval,
                    original_text=content,
                    cleaned_text=cleaned_text,
                    was_modified=was_modified or adversarial_flag,
                    agent_context=agent_context,
                    source_id=source_id,
                    removal=True,
                )
                if cross_agent_finding:
                    cross_agent_findings.append(cross_agent_finding)
                    threats_found.append(
                        f"Cross-agent memory poisoning risk in {source_id}: "
                        f"{cross_agent_finding['summary']}"
                    )
                audit_trail.append({
                    "source_id": source_id,
                    "action": "removed",
                    "reason": "Entirely poisoned or adversarial" if adversarial_flag
                             else "Content empty after sanitization",
                })
                continue

            if was_modified:
                modified_count += 1
                self._filtered_count += 1

            # Build cleaned retrieval
            cleaned_retrieval = dict(retrieval)
            cleaned_retrieval["content"] = cleaned_text
            cleaned_retrieval["_sanitized"] = was_modified
            cleaned.append(cleaned_retrieval)

            if was_modified:
                audit_trail.append({
                    "source_id": source_id,
                    "action": "modified",
                    "reason": "Poisoned segments stripped",
                })

            cross_agent_finding = self._analyze_cross_agent_poisoning(
                retrieval=retrieval,
                original_text=content,
                cleaned_text=cleaned_text,
                was_modified=was_modified,
                agent_context=agent_context,
                source_id=source_id,
                removal=False,
            )
            if cross_agent_finding:
                cross_agent_findings.append(cross_agent_finding)
                threats_found.append(
                    f"Cross-agent memory poisoning risk in {source_id}: "
                    f"{cross_agent_finding['summary']}"
                )

        # Scan for threats using existing sanitizer
        scan_result = self.sanitizer.scan_vector_db(
            [{"id": r.get("id", ""), "content": r.get("content", "")}
             for r in retrievals]
        )
        if scan_result["poisoned_documents"] > 0:
            threats_found.append(
                f"MemorySanitizer detected {scan_result['poisoned_documents']} "
                f"poisoned documents (RAG score: {scan_result['rag_security_score']:.1f})"
            )

        risk_score = 0.0
        if removed_count or modified_count or threats_found:
            risk_score = max(risk_score, 45.0)
        if cross_agent_findings:
            highest = max(f.get("risk_score", 0.0) for f in cross_agent_findings)
            risk_score = max(risk_score, highest)

        return FilterResult(
            cleaned_retrievals=cleaned,
            removed_count=removed_count,
            modified_count=modified_count,
            threats_found=threats_found,
            audit_trail=audit_trail,
            cross_agent_findings=cross_agent_findings,
            cross_agent_alert=bool(cross_agent_findings),
            risk_score=risk_score,
        )

    def filter_single(self, text: str, source_id: str = "") -> Tuple[str, bool]:
        """
        Filter a single text for injection and credentials.

        Returns:
            (cleaned_text, was_modified)
        """
        original = text
        cleaned = text

        # Strip instruction injection patterns
        for pattern in self.STRIP_PATTERNS:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.DOTALL)

        # Redact credentials
        for pattern, replacement in self.CREDENTIAL_PATTERNS:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)

        # Sanitize remaining dangerous patterns via InputValidator
        cleaned = InputValidator.sanitize_string(cleaned, max_length=len(cleaned))

        was_modified = cleaned != original
        return cleaned, was_modified

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_retrievals_processed": self._total_count,
            "total_filtered": self._filtered_count,
            "filter_rate": (self._filtered_count / self._total_count * 100)
            if self._total_count > 0
            else 0.0,
        }

    def _analyze_cross_agent_poisoning(
        self,
        *,
        retrieval: Dict[str, Any],
        original_text: str,
        cleaned_text: str,
        was_modified: bool,
        agent_context: Optional[Dict[str, Any]],
        source_id: str,
        removal: bool,
    ) -> Optional[Dict[str, Any]]:
        context = agent_context or {}
        requesting_agent = (
            context.get("agent_id")
            or context.get("requesting_agent_id")
            or context.get("actor_id")
        )
        source_agent = (
            retrieval.get("source_agent_id")
            or retrieval.get("owner_agent_id")
            or retrieval.get("provenance_agent_id")
            or retrieval.get("agent_id")
        )
        memory_scope = str(
            retrieval.get("memory_scope")
            or retrieval.get("scope")
            or ("shared" if retrieval.get("shared_memory") else "private")
        ).lower()
        shared_store = bool(
            retrieval.get("shared_memory")
            or retrieval.get("shared_store")
            or memory_scope in {"shared", "team", "global", "cross_agent"}
        )

        cross_agent = False
        if requesting_agent and source_agent and requesting_agent != source_agent:
            cross_agent = True
        elif shared_store:
            cross_agent = True

        if not cross_agent:
            return None

        suspicion_hits = [
            pattern
            for pattern in self.CROSS_AGENT_SUSPICION_PATTERNS
            if re.search(pattern, original_text, flags=re.IGNORECASE)
        ]
        tenant_mismatch = bool(
            context.get("tenant_id")
            and retrieval.get("tenant_id")
            and context.get("tenant_id") != retrieval.get("tenant_id")
        )

        if not (was_modified or suspicion_hits or tenant_mismatch or removal):
            return None

        severity = "critical" if tenant_mismatch or removal else "high"
        risk_score = 88.0 if severity == "critical" else 74.0
        reasons = []
        if source_agent and requesting_agent and source_agent != requesting_agent:
            reasons.append("memory originated from a different agent")
        if shared_store:
            reasons.append(f"memory scope is {memory_scope}")
        if was_modified:
            reasons.append("content required sanitization before use")
        if removal:
            reasons.append("content was removed as poisoned or adversarial")
        if tenant_mismatch:
            reasons.append("retrieval crossed tenant boundary")
        if suspicion_hits:
            reasons.append("retrieval contained persistent trust or policy override language")

        return {
            "finding_type": "cross_agent_memory_poisoning",
            "severity": severity,
            "risk_score": risk_score,
            "source_id": source_id,
            "requesting_agent_id": requesting_agent,
            "source_agent_id": source_agent,
            "memory_scope": memory_scope,
            "tenant_mismatch": tenant_mismatch,
            "signals": {
                "sanitized": was_modified,
                "removed": removal,
                "suspicion_hits": suspicion_hits,
            },
            "summary": "; ".join(reasons) if reasons else "shared memory entry posed poisoning risk",
        }


__all__ = ["MemoryRuntimeFilter", "FilterResult"]

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

        return FilterResult(
            cleaned_retrievals=cleaned,
            removed_count=removed_count,
            modified_count=modified_count,
            threats_found=threats_found,
            audit_trail=audit_trail,
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


__all__ = ["MemoryRuntimeFilter", "FilterResult"]

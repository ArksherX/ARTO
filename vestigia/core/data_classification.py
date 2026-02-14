#!/usr/bin/env python3
"""
Vestigia Data Classification & PII Scrubbing Engine
Phase 2: Production Hardening

Auto-detects PII (emails, phones, SSNs, credit cards, API keys, IPs)
and classifies events by sensitivity level. Supports GDPR/CCPA redaction.
"""

import re
import json
import logging
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ClassificationLevel(Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    field_path: str
    start: int
    end: int
    classification: ClassificationLevel


@dataclass
class ClassificationResult:
    level: ClassificationLevel
    pii_found: List[PIIMatch] = field(default_factory=list)
    fields_scanned: int = 0
    scrubbed: bool = False


# Built-in PII patterns
_DEFAULT_PATTERNS: List[Tuple[str, str, ClassificationLevel]] = [
    ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", ClassificationLevel.CONFIDENTIAL),
    ("phone_us", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", ClassificationLevel.CONFIDENTIAL),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", ClassificationLevel.RESTRICTED),
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b", ClassificationLevel.RESTRICTED),
    ("api_key", r"\b(?:sk_|pk_|api_|key_|bearer\s+)[a-zA-Z0-9_\-]{16,}\b", ClassificationLevel.RESTRICTED),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ClassificationLevel.INTERNAL),
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", ClassificationLevel.INTERNAL),
    ("jwt", r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", ClassificationLevel.RESTRICTED),
]

_REDACTION_LABELS = {
    "email": "[EMAIL_REDACTED]",
    "phone_us": "[PHONE_REDACTED]",
    "ssn": "[SSN_REDACTED]",
    "credit_card": "[CC_REDACTED]",
    "api_key": "[APIKEY_REDACTED]",
    "ipv4": "[IP_REDACTED]",
    "ipv6": "[IP_REDACTED]",
    "jwt": "[TOKEN_REDACTED]",
}


def _luhn_check(number: str) -> bool:
    """Validate a credit card number with the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class DataClassifier:
    """
    PII detection and data classification engine.

    Scans event dictionaries for sensitive data and can redact PII
    based on configurable classification levels.
    """

    def __init__(self, gdpr_mode: bool = False, ccpa_mode: bool = False):
        self.gdpr_mode = gdpr_mode
        self.ccpa_mode = ccpa_mode
        self.patterns: List[Tuple[str, re.Pattern, ClassificationLevel]] = []
        self._stats = {"events_scanned": 0, "pii_found": 0, "events_scrubbed": 0}

        for name, pattern, level in _DEFAULT_PATTERNS:
            self.patterns.append((name, re.compile(pattern, re.IGNORECASE), level))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_pattern(self, name: str, regex: str, level: ClassificationLevel = ClassificationLevel.CONFIDENTIAL):
        """Register a custom PII pattern."""
        self.patterns.append((name, re.compile(regex), level))
        _REDACTION_LABELS.setdefault(name, f"[{name.upper()}_REDACTED]")

    def detect_pii(self, text: str, field_path: str = "") -> List[PIIMatch]:
        """Return all PII matches found in *text*."""
        matches: List[PIIMatch] = []
        for name, regex, level in self.patterns:
            for m in regex.finditer(text):
                value = m.group()
                # Extra validation for credit cards
                if name == "credit_card":
                    if not _luhn_check(value):
                        continue
                matches.append(PIIMatch(
                    pii_type=name, value=value,
                    field_path=field_path,
                    start=m.start(), end=m.end(),
                    classification=level,
                ))
        return matches

    def classify_event(self, event: dict) -> ClassificationResult:
        """Scan all string fields of *event* and determine classification."""
        self._stats["events_scanned"] += 1
        result = ClassificationResult(level=ClassificationLevel.PUBLIC, fields_scanned=0)
        self._scan_dict(event, "", result)
        if result.pii_found:
            self._stats["pii_found"] += len(result.pii_found)
            # Highest-sensitivity PII determines event level
            result.level = max(
                (m.classification for m in result.pii_found),
                key=lambda c: list(ClassificationLevel).index(c),
            )
        return result

    def scrub_pii(self, event: dict, min_level: ClassificationLevel = ClassificationLevel.CONFIDENTIAL) -> dict:
        """Return a deep copy of *event* with PII above *min_level* redacted."""
        result = self.classify_event(event)
        if not result.pii_found:
            return event

        threshold = list(ClassificationLevel).index(min_level)
        scrubbed = json.loads(json.dumps(event))  # deep copy

        for match in result.pii_found:
            if list(ClassificationLevel).index(match.classification) >= threshold:
                self._redact_at_path(scrubbed, match.field_path, match.value, match.pii_type)

        self._stats["events_scrubbed"] += 1
        result.scrubbed = True
        return scrubbed

    def auto_scrub(self, event: dict) -> dict:
        """GDPR/CCPA compliant auto-scrubbing — scrubs everything INTERNAL and above."""
        if self.gdpr_mode or self.ccpa_mode:
            return self.scrub_pii(event, ClassificationLevel.INTERNAL)
        return self.scrub_pii(event, ClassificationLevel.CONFIDENTIAL)

    def get_classification_report(self) -> dict:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_dict(self, obj: Any, path: str, result: ClassificationResult):
        if isinstance(obj, dict):
            for key, value in obj.items():
                self._scan_dict(value, f"{path}.{key}" if path else key, result)
        elif isinstance(obj, (list, tuple)):
            for idx, item in enumerate(obj):
                self._scan_dict(item, f"{path}[{idx}]", result)
        elif isinstance(obj, str):
            result.fields_scanned += 1
            matches = self.detect_pii(obj, path)
            result.pii_found.extend(matches)

    @staticmethod
    def _redact_at_path(obj: dict, path: str, value: str, pii_type: str):
        """Replace *value* inside nested *obj* at the given dot-path."""
        label = _REDACTION_LABELS.get(pii_type, "[REDACTED]")
        parts = path.replace("[", ".[").split(".")
        current: Any = obj
        for part in parts[:-1]:
            if part.startswith("[") and part.endswith("]"):
                current = current[int(part[1:-1])]
            else:
                current = current.get(part, current)
        last = parts[-1] if parts else ""
        if isinstance(current, dict) and last in current and isinstance(current[last], str):
            current[last] = current[last].replace(value, label)
        elif isinstance(current, list):
            idx = int(last.strip("[]")) if last.startswith("[") else 0
            if idx < len(current) and isinstance(current[idx], str):
                current[idx] = current[idx].replace(value, label)


if __name__ == "__main__":
    clf = DataClassifier(gdpr_mode=True)
    sample = {
        "actor_id": "agent-007",
        "evidence": {
            "summary": "User john.doe@example.com accessed file",
            "metadata": {"ip": "192.168.1.42", "ssn": "123-45-6789"},
        },
    }
    result = clf.classify_event(sample)
    print(f"Classification: {result.level.value}")
    for m in result.pii_found:
        print(f"  {m.pii_type}: {m.value} at {m.field_path}")

    scrubbed = clf.scrub_pii(sample)
    print(f"\nScrubbed: {json.dumps(scrubbed, indent=2)}")
    print(f"\nReport: {clf.get_classification_report()}")

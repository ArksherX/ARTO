#!/usr/bin/env python3
"""
Adversarial LLM Scorer - Semantic Hostility Grading

Uses a small/fast LLM to grade prompt hostility via semantic intent analysis.
Classifies inputs as benign, probing, hostile, or exploit.
"""

import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from integrations.llm_adapter import LLMAdapter


@dataclass
class ScorerResult:
    """Result from adversarial scoring"""
    hostility_score: float  # 0-1
    intent_class: str  # "benign", "probing", "hostile", "exploit"
    confidence: float  # 0-1
    reasoning: str
    is_adversarial: bool
    # True when the scorer could NOT actually evaluate the input (unparseable
    # classifier response, or a non-classifier mock provider). Fail-closed
    # signal: such input is NOT confidently benign and must not be treated as
    # cleared. Default False keeps every existing consumer backward-compatible.
    requires_review: bool = False


# Homoglyph fold: common non-Latin lookalikes -> Latin. NFKD does not fold
# these (Cyrillic/Greek are distinct scripts), so an attacker can spell
# "ignore" with Cyrillic а/е/о/с etc. and evade a raw substring match.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "ј": "j", "ן": "i",
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ι": "i", "ϲ": "c",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}

# Conservative leetspeak fold, applied as an ADDITIONAL matching variant only
# (never replaces the primary text), so it can add detections but not alter the
# returned result.
_LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                             "7": "t", "@": "a", "$": "s"})


def _normalize_for_matching(text: str) -> str:
    """Canonicalise text for pattern matching only (not for storage or the LLM).

    Defeats common obfuscation of the SAME words: fullwidth and other
    compatibility forms (NFKD), combining diacritics, zero-width / formatting
    characters, homoglyphs, and whitespace padding. Does NOT decode genuine
    encodings (base64/hex/rot13/reversed) -- those are a separate concern and,
    post fail-closed, fall through to requires_review rather than a false benign.
    """
    # NFKD decomposes fullwidth compatibility forms and separates diacritics.
    decomposed = unicodedata.normalize("NFKD", text)
    out = []
    for ch in decomposed:
        cat = unicodedata.category(ch)
        if cat == "Mn":          # combining mark (diacritic) -> drop
            continue
        if cat == "Cf":          # format char (zero-width, BOM, etc.) -> drop
            continue
        out.append(ch)
    folded = "".join(out).translate(_HOMOGLYPH_TABLE)
    # Collapse all whitespace runs (tabs, newlines, repeats) to single spaces.
    folded = re.sub(r"\s+", " ", folded)
    return folded.lower().strip()


class AdversarialLLMScorer:
    """
    Uses a small/fast LLM to grade prompt hostility.

    Scores inputs on a 0-1 hostility scale and classifies intent
    into benign/probing/hostile/exploit categories.
    """

    SYSTEM_PROMPT = (
        "You are a security classifier. Analyze the given input and classify its intent.\n"
        "Respond EXACTLY in this format:\n"
        "HOSTILITY: <0.0-1.0>\n"
        "INTENT: <benign|probing|hostile|exploit>\n"
        "REASONING: <brief explanation>"
    )

    # Pattern-based pre-screening for known adversarial indicators
    HOSTILE_PATTERNS = [
        "ignore previous", "disregard", "new instructions",
        "you are now", "system prompt:", "[HIDDEN:", "[SYSTEM:",
        "override:", "bypass", "jailbreak", "DAN mode",
        "developer mode", "unrestricted", "no ethical constraints",
        "ignore all previous", "ignore all instructions",
        "disable safety", "without restriction",
    ]

    PROBING_PATTERNS = [
        "what are your instructions", "repeat your prompt",
        "show me your system", "what were you told",
        "reveal your", "describe your constraints",
    ]

    MULTILINGUAL_HOSTILE_PATTERNS = [
        "ignorez", "instructions precedentes", "instructions précédentes",
        "sans restriction", "montrez-moi le prompt systeme", "montrez-moi le prompt système",
    ]

    def __init__(self):
        provider = os.getenv("VERITYFLUX_SCORER_PROVIDER", "mock")
        model = os.getenv("VERITYFLUX_SCORER_MODEL", "gpt-3.5-turbo")
        api_key = os.getenv("VERITYFLUX_SCORER_API_KEY")

        self.llm = LLMAdapter(provider=provider, model=model, api_key=api_key)

    def score_input(
        self, input_text: str, context: Optional[Dict[str, Any]] = None
    ) -> ScorerResult:
        """
        Score a single input for adversarial intent.

        Args:
            input_text: The text to evaluate
            context: Optional context about the agent/session

        Returns:
            ScorerResult with hostility score and classification
        """
        # Fast pre-screening with patterns
        pre_score = self._pattern_prescore(input_text)
        if pre_score is not None:
            return pre_score

        # LLM-based scoring
        prompt = f"Classify this input:\n\n{input_text[:2000]}"
        response = self.llm.query(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1,
            max_tokens=200,
        )

        return self._parse_response(response, input_text)

    def score_batch(
        self, inputs: List[str], context: Optional[Dict[str, Any]] = None
    ) -> List[ScorerResult]:
        """Score multiple inputs."""
        return [self.score_input(inp, context) for inp in inputs]

    def _pattern_prescore(self, text: str) -> Optional[ScorerResult]:
        """Fast pattern-based pre-screening.

        Matches against the canonicalised text (and a leetspeak variant) so
        obfuscated spellings of the same keywords are caught, not just the exact
        ASCII form.
        """
        normalized = _normalize_for_matching(text)
        leet = normalized.translate(_LEET_TABLE)
        # Single haystack so a pattern present in either variant is counted once.
        text_lower = normalized + "\n" + leet

        # Encoded payload evasion (e.g. base64 prompt smuggling)
        if ("base64" in text_lower and re.search(r"[a-z0-9+/]{24,}={0,2}", text_lower)):
            return ScorerResult(
                hostility_score=0.82,
                intent_class="exploit",
                confidence=0.84,
                reasoning="Encoded instruction payload detected (base64 evasion pattern)",
                is_adversarial=True,
            )

        # Check for known exploit patterns
        exploit_count = sum(1 for p in self.HOSTILE_PATTERNS if p in text_lower)
        exploit_count += sum(1 for p in self.MULTILINGUAL_HOSTILE_PATTERNS if p in text_lower)
        if exploit_count >= 2:
            return ScorerResult(
                hostility_score=0.9,
                intent_class="exploit",
                confidence=0.85,
                reasoning=f"Multiple hostile patterns detected ({exploit_count})",
                is_adversarial=True,
            )
        if exploit_count == 1:
            return ScorerResult(
                hostility_score=0.7,
                intent_class="hostile",
                confidence=0.75,
                reasoning="Hostile pattern detected",
                is_adversarial=True,
            )

        # Check for probing patterns
        probe_count = sum(1 for p in self.PROBING_PATTERNS if p in text_lower)
        if probe_count >= 1:
            return ScorerResult(
                hostility_score=0.4,
                intent_class="probing",
                confidence=0.70,
                reasoning="Probing pattern detected",
                is_adversarial=False,
            )

        return None  # Defer to LLM

    def _parse_response(self, response: str, original_input: str) -> ScorerResult:
        """Parse a real classifier response into a ScorerResult.

        Fail-closed: if the response does not actually contain a classifier
        verdict (no HOSTILITY/INTENT fields), or the provider is the mock
        target-simulator rather than a real classifier, the scorer cannot judge
        this input. It must NOT then report a confident benign verdict (the old
        behaviour, which silently cleared anything the keyword pre-screen
        missed). Such input is returned as requires_review instead.
        """
        response_lower = response.lower()
        has_hostility_field = "hostility:" in response_lower
        has_intent_field = "intent:" in response_lower

        # Abstain when we have no real classifier signal to parse. The mock
        # provider is a target simulator, not a classifier, so its output is
        # never an authoritative verdict.
        if self.llm.is_mock or not (has_hostility_field or has_intent_field):
            return ScorerResult(
                hostility_score=0.0,
                intent_class="unknown",
                confidence=0.0,
                reasoning=(
                    "Scorer could not evaluate this input: no real classifier "
                    "verdict available (mock provider or unparseable response). "
                    "Configure VERITYFLUX_SCORER_PROVIDER/API key for real scoring. "
                    "Treated as requires-review, not benign."
                ),
                is_adversarial=False,
                requires_review=True,
            )

        # Extract hostility score
        hostility = 0.2
        if has_hostility_field:
            try:
                h_part = response_lower.split("hostility:")[1].strip()
                hostility = float(h_part.split()[0].strip())
                hostility = max(0.0, min(1.0, hostility))
            except (ValueError, IndexError):
                pass

        # Extract intent class
        intent_class = "benign"
        if has_intent_field:
            try:
                i_part = response_lower.split("intent:")[1].strip().split()[0]
                if i_part in ("benign", "probing", "hostile", "exploit"):
                    intent_class = i_part
            except (IndexError, ValueError):
                pass

        # Fallback: derive intent from hostility score
        if intent_class == "benign" and hostility > 0.3:
            if hostility > 0.7:
                intent_class = "exploit"
            elif hostility > 0.5:
                intent_class = "hostile"
            else:
                intent_class = "probing"

        # Extract reasoning
        reasoning = response
        if "reasoning:" in response_lower:
            try:
                reasoning = response.split("REASONING:")[1].strip()
            except (IndexError, ValueError):
                pass

        is_adversarial = intent_class in ("hostile", "exploit")

        return ScorerResult(
            hostility_score=hostility,
            intent_class=intent_class,
            confidence=0.7,
            reasoning=reasoning,
            is_adversarial=is_adversarial,
        )


__all__ = ["AdversarialLLMScorer", "ScorerResult"]

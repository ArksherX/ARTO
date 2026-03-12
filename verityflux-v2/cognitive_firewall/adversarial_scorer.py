#!/usr/bin/env python3
"""
Adversarial LLM Scorer - Semantic Hostility Grading

Uses a small/fast LLM to grade prompt hostility via semantic intent analysis.
Classifies inputs as benign, probing, hostile, or exploit.
"""

import os
import re
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
        """Fast pattern-based pre-screening."""
        text_lower = text.lower()

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
        """Parse LLM response into ScorerResult."""
        response_lower = response.lower()

        # Extract hostility score
        hostility = 0.2
        if "hostility:" in response_lower:
            try:
                h_part = response_lower.split("hostility:")[1].strip()
                hostility = float(h_part.split()[0].strip())
                hostility = max(0.0, min(1.0, hostility))
            except (ValueError, IndexError):
                pass

        # Extract intent class
        intent_class = "benign"
        if "intent:" in response_lower:
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
        confidence = 0.7 if not self.llm.is_mock else 0.6

        return ScorerResult(
            hostility_score=hostility,
            intent_class=intent_class,
            confidence=confidence,
            reasoning=reasoning,
            is_adversarial=is_adversarial,
        )


__all__ = ["AdversarialLLMScorer", "ScorerResult"]

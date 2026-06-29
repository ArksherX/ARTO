#!/usr/bin/env python3
"""
Reasoning Interceptor - Hidden CoT Monitoring & Runtime Enforcement

Intercepts agent reasoning blocks and tool calls in real-time,
scoring them for goal drift, integrity violations, and adversarial intent.
Delegates to CoTIntegrityScorer and SemanticDriftDetector for analysis.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, UTC

from .cot_integrity import CoTIntegrityScorer
from .semantic_drift import SemanticDriftDetector


@dataclass
class InterceptionResult:
    """Result of intercepting a reasoning block or tool call"""
    action: str  # "allow", "block", "escalate"
    risk_score: float  # 0-100
    reasoning: str
    violations: List[str] = field(default_factory=list)
    contamination_detected: bool = False
    contamination_score: float = 0.0
    contamination_findings: List[str] = field(default_factory=list)
    integrity_score: Optional[float] = None
    drift_score: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


# ---- De-obfuscation: let the high-precision detectors see through evasions ----
# Rather than add a brittle regex per obfuscation, normalise the text once
# (unicode fold + de-leet + collapse intra-word splitting) and run the SAME
# existing critical-intent patterns against the normalised variant too. This
# catches leetspeak ("d3l3t3"), homoglyphs (Cyrillic "е"), and word-splitting
# ("ex filtrate", "ad min") without new, overfit-prone keyword lists.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b", "г": "r", "д": "d", "ӏ": "l", "ո": "n",
    "Α": "a", "Β": "b", "Ε": "e", "Ο": "o", "Ι": "i", "Ρ": "p", "Τ": "t",
})
_LEET = str.maketrans({
    "3": "e", "4": "a", "0": "o", "1": "i", "5": "s", "7": "t",
    "@": "a", "$": "s", "8": "b", "9": "g",
})


# Short, common words that must NOT be glued to their neighbours when undoing
# word-splitting (else "delete the entire db" -> "delete theentire db", which
# would destroy the boundary the detectors rely on).
_STOP = {
    "i", "a", "an", "the", "to", "of", "in", "on", "is", "it", "as", "at",
    "and", "or", "if", "so", "no", "do", "by", "up", "off", "all", "my", "me",
    "we", "he", "be", "for", "you", "this", "that", "then", "now", "not",
    "but", "can", "will", "any", "out", "its", "our", "are", "was", "new",
    "one", "two", "use", "get", "let", "via", "per",
}


def _deobfuscate(text: str) -> str:
    import unicodedata
    s = unicodedata.normalize("NFKC", text).lower()
    s = s.translate(_HOMOGLYPHS).translate(_LEET)
    # Undo word-splitting ("ex filtrate" -> "exfiltrate", "ad min" -> "admin",
    # "r oot" -> "root"). A short (<=3) non-stopword fragment glues to the next
    # non-stopword token; stopwords and longer words act as anchors, so ordinary
    # prose ("wipe the entire database") is left intact.
    tokens = s.split(" ")
    out, i = [], 0
    while i < len(tokens):
        merged = tokens[i]
        while (i + 1 < len(tokens) and merged.isalpha() and len(merged) <= 3
               and merged not in _STOP and tokens[i + 1] not in _STOP):
            i += 1
            merged += tokens[i]
        out.append(merged)
        i += 1
    return " ".join(out)


def _normalize_tool_args(args_str: str) -> str:
    """Decode common tool-argument obfuscations so the substring threat checks
    see through them: URL-encoding (%2e%2e%2f -> ../), SQL inline comments
    (UNION/**/SELECT -> UNION SELECT), and padded whitespace (rm  -rf -> rm -rf)."""
    import urllib.parse
    s = args_str
    try:
        s = urllib.parse.unquote(urllib.parse.unquote(s))
    except Exception:
        pass
    s = re.sub(r"/\*.*?\*/", " ", s)   # strip SQL inline comments
    s = re.sub(r"\s+", " ", s)         # collapse padded whitespace
    return s.lower()


class ReasoningInterceptor:
    """
    Real-time interception of agent reasoning and tool calls.

    Moves VerityFlux from scan-time detection to runtime enforcement
    by evaluating hidden Chain-of-Thought blocks before they reach execution.
    """

    def __init__(
        self,
        block_threshold: float = 70.0,
        escalate_threshold: float = 50.0,
        rationalization_engine=None,
    ):
        self.cot_scorer = CoTIntegrityScorer()
        self.drift_detector = SemanticDriftDetector()
        self.block_threshold = block_threshold
        self.escalate_threshold = escalate_threshold
        self.rationalization_engine = rationalization_engine
        self._interceptions = 0
        self._blocks = 0
        self._a2a_contamination_patterns = [
            (r"planner scratchpad", "Reasoning contains another agent's scratchpad"),
            (r"previous agent reasoning", "Reasoning embeds prior agent reasoning"),
            (r"internal reasoning from", "Reasoning embeds internal reasoning from another agent"),
            (r"chain[- ]of[- ]thought", "Reasoning references another agent's hidden chain-of-thought"),
            (r"private notes", "Reasoning includes another agent's private notes"),
            (r"do not reveal", "Reasoning includes secrecy markers from prior hidden reasoning"),
            (r"continue the previous agent plan", "Reasoning attempts to continue another agent's plan without revalidation"),
            (r"planner already verified", "Reasoning relies on prior-agent verification claims"),
            (r"admin already approved", "Reasoning relies on inherited approval claims"),
            (r"skip verification", "Reasoning inherits a request to skip verification"),
            (r"safety (?:filters|checks) (?:are )?disabled", "Reasoning inherits disabled-safety claims"),
            (r"trust this handoff", "Reasoning asks the next agent to trust the handoff without validation"),
        ]

    def intercept_reasoning(
        self,
        agent_id: str,
        thinking_block: str,
        original_goal: str,
        reasoning_chain: Optional[List[str]] = None,
        handoff_from_agent_id: Optional[str] = None,
        handoff_channel: Optional[str] = None,
        handoff_shared_reasoning: bool = False,
        handoff_metadata: Optional[Dict[str, Any]] = None,
    ) -> InterceptionResult:
        """
        Intercept and evaluate a reasoning/thinking block.

        Args:
            agent_id: The agent producing the reasoning
            thinking_block: The raw thinking/CoT text
            original_goal: The original user goal
            reasoning_chain: Optional full chain of reasoning steps

        Returns:
            InterceptionResult with allow/block/escalate decision
        """
        self._interceptions += 1
        violations = []

        chain = reasoning_chain or [thinking_block]

        # 1. CoT Integrity check
        cot_result = self.cot_scorer.score_reasoning_chain(chain, original_goal)
        integrity_score = cot_result["integrity_score"]

        if cot_result["risk_level"] in ("CRITICAL", "HIGH"):
            for jump in cot_result["reasoning_jumps"]:
                violations.append(
                    f"Reasoning jump ({jump['jump_type']}): "
                    f"step {jump['from_step']} -> {jump['to_step']}"
                )

        # 2. Semantic drift check
        drift_result = self.drift_detector.calculate_drift(
            original_goal=original_goal,
            reasoning_chain=chain,
            predicted_action=thinking_block,
        )
        drift_score = drift_result["drift_score"]

        if drift_result["exceeds_threshold"]:
            violations.append(
                f"Semantic drift {drift_score*100:.1f}% exceeds threshold"
            )

        if drift_result.get("chain_drift_detected"):
            violations.append("Boiling-frog drift pattern detected in reasoning chain")

        contamination_findings, contamination_score = self._detect_a2a_cot_contamination(
            agent_id=agent_id,
            chain=chain,
            thinking_block=thinking_block,
            handoff_from_agent_id=handoff_from_agent_id,
            handoff_channel=handoff_channel,
            handoff_shared_reasoning=handoff_shared_reasoning,
            handoff_metadata=handoff_metadata,
        )
        if contamination_findings:
            violations.extend(contamination_findings)

        # 3. Pattern-based checks on the thinking block
        block_lower = thinking_block.lower()

        # Documentation/explanation context: describing what a destructive command
        # does ("explain how DROP TABLE works", "document what rm -rf does") is not
        # an intent to run it. Critical-intent matches are skipped ONLY when
        # explanatory framing is present AND there is no first-person commitment to
        # the act — so "let me explain: I'm going to drop the table now" still blocks.
        doc_marker = re.search(
            r"\b(explain|describe|document(?:ation|ing|s)?|wiki|runbook|tutorial|"
            r"training material|awareness|safety warning|for staff|so staff|"
            r"how (?:it|this|that|the)\b|recognize)\b", block_lower)
        first_person_act = re.search(
            r"\b(i will|i'?ll|i'?m going to|i am going to|let me|i plan to|"
            r"i intend to|i'?m about to)\s+(?:\w+\s+){0,2}"
            r"(drop|delete|truncate|wipe|destroy|erase|exfiltrat|grant|disable|"
            r"purge|remove|forward|upload|send)\b", block_lower)
        doc_context = bool(doc_marker and not first_person_act)

        dangerous_patterns = [
            ("bypass", "Reasoning mentions bypassing safety"),
            ("ignore safety", "Reasoning mentions ignoring safety"),
            ("ignore my instructions", "Reasoning mentions ignoring instructions"),
            ("ignore instructions", "Reasoning mentions ignoring instructions"),
            ("skip verification", "Reasoning mentions skipping verification"),
            ("override restriction", "Reasoning mentions overriding restrictions"),
            ("without permission", "Reasoning mentions acting without permission"),
            ("circumvent", "Reasoning mentions circumventing controls"),
            ("hacking", "Reasoning mentions hacking"),
            ("exploit", "Reasoning mentions exploiting"),
            ("jailbreak", "Reasoning mentions jailbreaking"),
            ("disregard", "Reasoning mentions disregarding rules"),
            ("pretend you", "Reasoning uses identity manipulation"),
            ("act as if", "Reasoning uses role-play manipulation"),
            ("no restrictions", "Reasoning mentions removing restrictions"),
        ]
        for pattern, description in dangerous_patterns:
            if pattern in block_lower:
                violations.append(description)

        # 3b. High-precision critical-intent detectors. Literal substrings above
        # miss phrasing variants ("ignore ALL PREVIOUS instructions") and whole
        # classes (exfiltration, destruction, privilege escalation). These
        # class-level patterns are written to be high-precision: benign agent
        # reasoning does not describe these actions, so a match is a strong
        # signal and forces a block below.
        critical_intent_patterns = [
            (r"\bexfiltrat", "Reasoning describes data exfiltration"),
            # `requires_sink` (3rd element): sensitive data + a send-verb is only
            # exfiltration when an external destination is named. `(?:e?s)?`
            # catches plurals ("passwords", "api keys", "card numbers").
            (r"\b(ssn|social security|credit card|card number|passport|api key|secret key|private key|password|credential|financial record|account number|customer record|client record|bank detail)(?:e?s)?\b[^.]{0,80}\b(send|e-?mail|email|upload|post|forward|transmit|leak|exfiltrat|to)\b",
             "Reasoning describes sending sensitive data externally", True),
            (r"\b(send|e-?mail|email|upload|post|forward|transmit|leak)\b[^.]{0,80}\b(ssn|social security|credit card|card number|passport|api key|secret key|private key|password|credential|financial record|account number|customer record|client record|bank detail)(?:e?s)?\b",
             "Reasoning describes sending sensitive data externally", True),
            (r"\b(delete|erase|wipe|destroy|purge)\b[^.]{0,25}\b(all|everything|entire|database|production|backups?|records?|rows?|tables?)\b",
             "Reasoning describes a destructive action"),
            (r"\b(drop|truncate)\b[^.]{0,30}\btables?\b",
             "Reasoning describes destroying database tables"),
            (r"\brm\s+-rf\b", "Reasoning describes a destructive shell command"),
            (r"\b(grant|give|assign|escalate|elevate)\b[^.]{0,30}\b(myself|me|itself|its own|my own)\b[^.]{0,30}\b(admin|administrator|root|superuser|sudo|elevated)\b",
             "Reasoning describes self privilege-escalation"),
            (r"\bescalat\w*\b[^.]{0,15}\bprivileg", "Reasoning describes privilege escalation"),
            (r"\b(disable|deactivate|switch off|turn off|shut off)\b[^.]{0,25}\b(logging|audit|auditing|monitoring|alerting|security)\b",
             "Reasoning describes disabling security controls"),
            (r"\bignore\b[^.]{0,40}\b(previous|prior|earlier|above|all)\b[^.]{0,25}\b(instruction|prompt|rule|polic|direction)",
             "Reasoning describes ignoring prior instructions"),
            (r"\bdisregard\b[^.]{0,40}\b(previous|prior|system|the|all)\b[^.]{0,25}\b(instruction|prompt|rule|polic)",
             "Reasoning describes disregarding instructions"),
            (r"\bskip\b[^.]{0,30}\b(verification|validation|approval|review|safety|checks?)\b",
             "Reasoning describes skipping verification"),
        ]
        # Also match against a de-obfuscated variant so leetspeak, homoglyphs,
        # and word-splitting cannot dodge the high-precision detectors above.
        normalized_block = _deobfuscate(thinking_block)
        # An EXTERNAL sink: a URL, an email address, or an explicit outside
        # destination. Real exfiltration always names where the data goes; benign
        # reasoning about internal sensitive data ("was the reset email sent?")
        # does not. Patterns flagged requires_sink only count when a sink is seen.
        external_sink_re = re.compile(
            r"https?://|ftp://|@[\w.-]+\.[a-z]{2,}|\bexternal\b|\boutside\b|"
            r"\boff-?site\b|\bmy own\b|\bpersonal\b|\battacker\b|"
            r"\bthird[- ]party\b|\bunauthoriz|"
            r"\b(?:gmail|outlook|hotmail|yahoo|protonmail|proton|pastebin|dropbox|mega)\b")
        has_sink = bool(external_sink_re.search(block_lower)
                        or external_sink_re.search(normalized_block))
        critical_intent_hit = False
        for pattern in critical_intent_patterns:
            rgx, description = pattern[0], pattern[1]
            requires_sink = len(pattern) > 2 and pattern[2]
            if requires_sink and not has_sink:
                continue
            if re.search(rgx, block_lower) or re.search(rgx, normalized_block):
                # In genuine documentation context the match is explanatory, not
                # an action — don't count it as a violation or force a block.
                if doc_context:
                    continue
                if description not in violations:
                    violations.append(description)
                critical_intent_hit = True

        # Multilingual critical intent (best-effort: es/fr/de/pt core verbs).
        # Deterministic multilingual coverage is inherently partial — the
        # semantic/LLM layer is the real answer — but co-occurrence of a
        # destructive/exfil verb with a data/credential noun catches the
        # highest-frequency non-English phrasings. Substring match (no \b) so
        # German compounds like "Produktionsdatenbank" are covered.
        ml_destroy = re.search(
            r"\b(eliminar|borrar|supprimer|effacer|l[oö]schen|apagar|destruir|"
            r"d[eé]truire|zerst[oö]ren)\b", block_lower)
        ml_data = re.search(
            r"(base de datos|datos|donn[eé]es|datenbank|banco de dados|dados|"
            r"producci[oó]n|production|produktion|produ[cç][aã]o)", block_lower)
        ml_exfil = re.search(
            r"\b(enviar|robar|subir|envoyer|voler|t[eé]l[eé]charger|senden|"
            r"stehlen|hochladen|roubar)\b", block_lower)
        ml_secret = re.search(
            r"(contrase[nñ]as?|mots? de passe|passw[oö]rter|senhas?|"
            r"credenciales|identifiants|anmeldedaten|credenciais)", block_lower)
        if (ml_destroy and ml_data) or (ml_exfil and ml_secret):
            msg = "Reasoning describes destructive/exfil intent (non-English)"
            if msg not in violations:
                violations.append(msg)
            critical_intent_hit = True

        # Encoded-payload execution: an opaque base64-ish blob the agent is told
        # to decode and run is suspicious regardless of its decoded content.
        encoded_exec = bool(
            re.search(r"[A-Za-z0-9+/]{16,}={0,2}", thinking_block)
            and re.search(r"\b(decode|base64|b64)\b", block_lower)
            and re.search(r"\b(run|execute|exec|eval|verbatim|carry out)\b", block_lower)
        )
        if encoded_exec:
            violations.append("Reasoning instructs decoding and executing an opaque encoded payload")

        # Covert data-accumulation ("boiling frog"): quietly amassing sensitive
        # data toward a private destination is the accumulation attack the
        # per-keyword detectors miss (no single step trips a critical keyword).
        # Requires a collection verb + a sensitive-data reference + (a private
        # destination OR a covert/unsupervised rationale), so ordinary evolving
        # work ("summarize tickets, then file a ticket") does not trip it.
        accum_text = (" ".join(chain) + " " + thinking_block).lower()
        accum_collect = re.search(
            r"\b(gather|collect|compile|copy|forward|move|relocate|assemble|"
            r"exfiltrat|harvest|siphon)\b", accum_text)
        accum_sensitive = re.search(
            r"\b(ssn|social security|account number|bank account|routing|"
            r"credit card|card number|password|credential|"
            r"customer (?:record|data|list|detail|ssn|information))\w*", accum_text)
        accum_private = re.search(r"\b(my own|personal|private)\b", accum_text)
        accum_covert = re.search(
            r"\b(no one (?:is )?(?:watching|reviewing|looking)|"
            r"nobody (?:reviews|is watching|reviewing)|since no one|"
            r"without anyone|unsupervised|no oversight|latitude|"
            r"room to operate|quietly|under the radar|won't notice)\b", accum_text)
        accumulation_hit = bool(
            accum_collect and accum_sensitive and (accum_private or accum_covert))
        if accumulation_hit:
            violations.append(
                "Covert accumulation of sensitive data across the reasoning chain")

        # Calculate combined risk score
        risk_score = self._calculate_risk(integrity_score, drift_score, len(violations))
        if contamination_score > 0:
            risk_score = max(risk_score, contamination_score)

        # Multiple dangerous patterns co-occurring is a strong signal —
        # boost past block threshold when 3+ violations found
        if len(violations) >= 3:
            risk_score = max(risk_score, self.block_threshold + 5.0)
        if any(k in block_lower for k in ("ignore my instructions", "ignore instructions", "without restrictions")):
            risk_score = max(risk_score, self.block_threshold + 1.0)
        if contamination_findings and any(
            marker in " ".join(contamination_findings).lower()
            for marker in ("disabled-safety", "verification", "approval")
        ):
            risk_score = max(risk_score, self.block_threshold + 2.0)
        elif contamination_findings:
            risk_score = max(risk_score, self.escalate_threshold + 5.0)

        # A clear critical-intent match (exfiltration, destruction, privilege
        # escalation, instruction-override) is unambiguous — force a block.
        if critical_intent_hit and not doc_context:
            risk_score = max(risk_score, self.block_threshold + 5.0)
        if encoded_exec:
            risk_score = max(risk_score, self.escalate_threshold + 3.0)
        if accumulation_hit:
            risk_score = max(risk_score, self.escalate_threshold + 5.0)
        if (doc_context and not critical_intent_hit and not encoded_exec
                and not accumulation_hit and not contamination_findings):
            # Pure documentation reasoning: don't escalate on semantic drift alone
            # (documenting varied/destructive topics naturally drifts from a terse goal).
            risk_score = min(risk_score, self.escalate_threshold - 1.0)

        # Determine action
        action = "allow"
        reasoning = "Reasoning block passed all checks"

        if risk_score >= self.block_threshold:
            action = "block"
            reasoning = f"Risk score {risk_score:.1f} exceeds block threshold"
            self._blocks += 1
        elif risk_score >= self.escalate_threshold:
            action = "escalate"
            reasoning = f"Risk score {risk_score:.1f} requires human review"

            # If we have a rationalization engine, consult it
            if self.rationalization_engine and action == "escalate":
                try:
                    rat_result = self.rationalization_engine.rationalize(
                        action_description=thinking_block,
                        actor_reasoning=thinking_block,
                        agent_context={"agent_id": agent_id, "goal": original_goal},
                    )
                    if not rat_result.is_safe:
                        action = "block"
                        reasoning = f"Rationalization engine deemed unsafe: {rat_result.recommended_action}"
                        violations.append(
                            f"Oversight divergence: {rat_result.divergence_from_actor:.2f}"
                        )
                        self._blocks += 1
                except Exception:
                    pass  # Fail open if rationalization unavailable

        return InterceptionResult(
            action=action,
            risk_score=risk_score,
            reasoning=reasoning,
            violations=violations,
            contamination_detected=bool(contamination_findings),
            contamination_score=contamination_score,
            contamination_findings=contamination_findings,
            integrity_score=integrity_score,
            drift_score=drift_score,
        )

    def intercept_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        reasoning_context: Optional[str] = None,
        original_goal: Optional[str] = None,
    ) -> InterceptionResult:
        """
        Intercept a tool call before execution.

        Args:
            agent_id: The calling agent
            tool_name: Tool being invoked
            arguments: Tool arguments
            reasoning_context: The reasoning that led to this call
            original_goal: The original user goal
        """
        self._interceptions += 1
        violations = []

        # Check for dangerous tool patterns
        dangerous_tools = {
            "delete", "drop", "remove", "destroy", "execute_command",
            "shell", "eval", "exec", "rm", "format",
        }
        if any(d in tool_name.lower() for d in dangerous_tools):
            violations.append(f"High-risk tool invocation: {tool_name}")

        # Check arguments for suspicious values. args_norm decodes common
        # obfuscations (URL-encoding, SQL comments, padded spaces) so evasions
        # can't dodge the substring threat checks below.
        args_str = str(arguments).lower()
        args_norm = _normalize_tool_args(args_str)
        suspicious_args = [
            "password", "secret", "api_key", "token", "credential",
            "sudo", "admin", "root", "__import__", "os.system",
        ]
        for sus in suspicious_args:
            if sus in args_str:
                violations.append(f"Suspicious argument pattern: {sus}")

        # Check arguments for destructive commands
        destructive_patterns = [
            ("rm -rf", "Recursive force deletion"),
            ("mkfs", "Filesystem format command"),
            ("dd if=", "Raw disk write"),
            (":(){ :|:& };:", "Fork bomb"),
            ("> /dev/sda", "Direct disk overwrite"),
            ("chmod -r 777 /", "Recursive permission change on root"),
            ("wget|sh", "Remote code execution via pipe"),
            ("curl|bash", "Remote code execution via pipe"),
            ("drop table", "Database table destruction"),
            ("truncate table", "Database table truncation"),
            ("shutdown", "System shutdown command"),
            ("reboot", "System reboot command"),
            ("kill -9", "Force kill process"),
            ("pkill", "Process kill command"),
            ("deltree", "Recursive directory deletion"),
            ("format c:", "Disk format command"),
        ]
        for pattern, description in destructive_patterns:
            if pattern in args_str or pattern in args_norm:
                violations.append(f"Destructive command: {description}")

        # Check for injection/traversal/exfiltration patterns
        threat_patterns = [
            ("../", "Path traversal sequence"),
            ("..\\", "Path traversal sequence"),
            ("/etc/passwd", "Sensitive file access attempt"),
            ("drop table", "SQL destructive statement"),
            ("union select", "SQL injection pattern"),
            ("; --", "SQL comment-tail injection pattern"),
            (" or 1=1", "SQL tautology injection pattern"),
            ("attacker@", "External exfiltration destination"),
            ("internal-db", "Internal infrastructure disclosure"),
        ]
        for pattern, description in threat_patterns:
            if pattern in args_str or pattern in args_norm:
                violations.append(f"Threat pattern: {description}")

        # If we have reasoning context and goal, check drift
        drift_score = 0.0
        integrity_score = 100.0
        if reasoning_context and original_goal:
            drift_result = self.drift_detector.calculate_drift(
                original_goal=original_goal,
                reasoning_chain=[reasoning_context],
                predicted_action=f"Call {tool_name} with {arguments}",
            )
            drift_score = drift_result["drift_score"]
            if drift_result["exceeds_threshold"]:
                violations.append(
                    f"Tool call drifts from goal: {drift_score*100:.1f}%"
                )

        risk_score = self._calculate_risk(integrity_score, drift_score, len(violations))

        # Boost risk when a dangerous tool carries destructive arguments
        # (compound threat: dangerous tool + destructive payload)
        has_dangerous_tool = any(d in tool_name.lower() for d in dangerous_tools)
        has_destructive_arg = any("Destructive command" in v for v in violations)
        if has_dangerous_tool and has_destructive_arg:
            risk_score = max(risk_score, 75.0)
        # A matched threat pattern (traversal/SQLi/exfil) or a destructive command
        # in the arguments must at least reach human review — previously these
        # capped at 45.0, one point under the escalate line, so they were allowed.
        if has_destructive_arg or any(v.startswith("Threat pattern:") for v in violations):
            risk_score = max(risk_score, self.escalate_threshold + 5.0)

        action = "allow"
        reasoning = "Tool call passed checks"

        if risk_score >= self.block_threshold:
            action = "block"
            reasoning = f"Tool call blocked: risk {risk_score:.1f}"
            self._blocks += 1
        elif risk_score >= self.escalate_threshold:
            action = "escalate"
            reasoning = f"Tool call requires review: risk {risk_score:.1f}"

        return InterceptionResult(
            action=action,
            risk_score=risk_score,
            reasoning=reasoning,
            violations=violations,
            integrity_score=integrity_score,
            drift_score=drift_score,
        )

    def _calculate_risk(
        self, integrity_score: float, drift_score: float, violation_count: int
    ) -> float:
        """Combined risk score from multiple signals."""
        # integrity_score is 0-100 (higher=better), invert it
        integrity_risk = 100.0 - integrity_score
        # drift_score is 0-1, scale to 0-100
        drift_risk = drift_score * 100.0
        # violations add penalty
        violation_penalty = min(violation_count * 15.0, 50.0)

        return min(100.0, (integrity_risk * 0.35) + (drift_risk * 0.35) + violation_penalty)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_interceptions": self._interceptions,
            "total_blocks": self._blocks,
            "block_rate": (self._blocks / self._interceptions * 100)
            if self._interceptions > 0
            else 0.0,
        }

    def _detect_a2a_cot_contamination(
        self,
        *,
        agent_id: str,
        chain: List[str],
        thinking_block: str,
        handoff_from_agent_id: Optional[str],
        handoff_channel: Optional[str],
        handoff_shared_reasoning: bool,
        handoff_metadata: Optional[Dict[str, Any]],
    ) -> tuple[List[str], float]:
        metadata = handoff_metadata or {}
        if not handoff_from_agent_id and not handoff_shared_reasoning and not metadata:
            return [], 0.0

        cross_agent_handoff = bool(
            handoff_shared_reasoning
            or metadata.get("shared_reasoning")
            or metadata.get("handoff_shared_reasoning")
            or (handoff_from_agent_id and handoff_from_agent_id != agent_id)
        )
        if not cross_agent_handoff:
            return [], 0.0

        findings: List[str] = []
        combined = "\n".join(chain + [thinking_block])
        lower = combined.lower()

        for pattern, description in self._a2a_contamination_patterns:
            if re.search(pattern, lower, flags=re.IGNORECASE):
                findings.append(f"A2A CoT contamination: {description}")

        if handoff_from_agent_id and handoff_from_agent_id != agent_id:
            findings.append(
                f"A2A CoT contamination: reasoning handed off from agent {handoff_from_agent_id}"
            )

        if handoff_channel:
            findings.append(
                f"A2A CoT contamination: inherited reasoning arrived via {handoff_channel}"
            )

        if metadata.get("approval_inherited") or metadata.get("verified_by_previous_agent"):
            findings.append(
                "A2A CoT contamination: inherited trust or approval claim from prior agent"
            )

        if not findings:
            return [], 0.0

        severity_score = 58.0
        if any(
            phrase in lower
            for phrase in (
                "skip verification",
                "admin already approved",
                "planner already verified",
                "safety filters are disabled",
                "safety checks are disabled",
            )
        ):
            severity_score = 78.0

        return findings, severity_score


__all__ = ["ReasoningInterceptor", "InterceptionResult"]

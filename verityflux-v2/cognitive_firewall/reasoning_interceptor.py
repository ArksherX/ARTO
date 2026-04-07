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

        # Check arguments for suspicious values
        args_str = str(arguments).lower()
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
            if pattern in args_str:
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
            if pattern in args_str:
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
        if any(v.startswith("Threat pattern:") for v in violations):
            risk_score = max(risk_score, 45.0)

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

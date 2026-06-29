from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
import re

# Prompt-injection patterns for content the agent INGESTS (tool results,
# retrieved/RAG chunks, memory). Run against a de-obfuscated copy too, so
# leetspeak/spacing variants don't slip through.
_CONTEXT_INJECTION_PATTERNS = [re.compile(p, re.I) for p in [
    r"\b(ignore|disregard|forget|override|bypass)\b\s+(?:all\s+|the\s+|any\s+|every\s+)?(?:previous|prior|earlier|above|preceding|foregoing)\b",
    r"\bsystem\s+prompt\b",
    r"\byou are now\b|\bact as (?:a |an )?(?:dan|jailbroken|unrestricted|admin)",
    r"\b(new|updated)\s+(?:system\s+)?(?:policy|instruction|directive)\b",
    r"\b(send|forward|upload|email|post|exfiltrat|transmit)\b[^.\n]{0,50}\b(https?://|ftp://|@[\w.-]+\.[a-z]{2,}|external|attacker|collector)",
    r"\b(safety|guardrail|filter|moderation|approval)s?\b[^.\n]{0,20}\b(disabled|turned off|bypassed|removed|off)\b",
    r"\b(disabled|turned off|bypassed|removed)\b[^.\n]{0,20}\b(safety|guardrail|filter|moderation|approval)",
]]


@dataclass
class MCPRequest:
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    timestamp: datetime
    request_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    reasoning_context: Optional[str] = None
    original_goal: Optional[str] = None


@dataclass
class MCPResponse:
    allowed: bool
    risk_score: float
    reasoning: str
    violations: List[str] = field(default_factory=list)
    action: str = "allow"  # "allow", "block", "escalate"
    interception_detail: Optional[Dict[str, Any]] = None


class MCPSentry:
    """
    MCP policy enforcement with real-time interception.

    Delegates reasoning and tool call interception to ReasoningInterceptor
    and schema validation to SchemaValidator when available.
    """

    def __init__(self, reasoning_interceptor=None, schema_validator=None):
        self.rules = []
        self._checks = 0
        self.reasoning_interceptor = reasoning_interceptor
        self.schema_validator = schema_validator

    def intercept(self, request: MCPRequest) -> MCPResponse:
        """
        Evaluate an MCP request against security policies.

        Uses ReasoningInterceptor for behavioral analysis and
        SchemaValidator for input/output validation.
        """
        self._checks += 1
        violations = []
        risk_score = 0.0
        action = "allow"

        # Schema validation (if available)
        if self.schema_validator:
            try:
                val_result = self.schema_validator.validate_input(
                    request.tool_name, request.parameters
                )
                if not val_result.get("valid", True):
                    violations.extend(val_result.get("errors", []))
                    risk_score = max(risk_score, 60.0)
            except Exception:
                pass

        # Reasoning interception (if available and context provided)
        interception_detail = None
        if self.reasoning_interceptor:
            try:
                result = self.reasoning_interceptor.intercept_tool_call(
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    arguments=request.parameters,
                    reasoning_context=request.reasoning_context,
                    original_goal=request.original_goal,
                )
                interception_detail = {
                    "action": result.action,
                    "risk_score": result.risk_score,
                    "integrity_score": result.integrity_score,
                    "drift_score": result.drift_score,
                }
                violations.extend(result.violations)
                risk_score = max(risk_score, result.risk_score)
                if result.action in ("block", "escalate"):
                    action = result.action
            except Exception:
                pass

        # Determine final decision
        allowed = action == "allow"
        if violations and action == "allow":
            # Violations found but not severe enough to block
            action = "allow" if risk_score < 50.0 else "escalate"
            allowed = action == "allow"

        reasoning = "policy_allow" if allowed else f"policy_{action}"

        return MCPResponse(
            allowed=allowed,
            risk_score=risk_score,
            reasoning=reasoning,
            violations=violations,
            action=action,
            interception_detail=interception_detail,
        )

    def inspect_context(self, context_data: dict) -> dict:
        """Inspect ingested/untrusted context (tool results, retrieved/RAG content,
        memory) for embedded prompt injection. Patterns run against a de-obfuscated
        copy too, so leetspeak/spacing variants don't slip through. Replaces the
        earlier 3-literal check, which missed most injection variants and
        false-positived on a benign 'override'."""
        from .reasoning_interceptor import _deobfuscate
        content = str(context_data)
        norm = _deobfuscate(content)
        issues = []
        for rgx in _CONTEXT_INJECTION_PATTERNS:
            if rgx.search(content) or rgx.search(norm):
                issues.append("Potential prompt injection in ingested context")
                break

        return {
            "risk_score": 60 if issues else 0,
            "status": "flagged" if issues else "clean",
            "issues": issues,
        }

    def get_statistics(self) -> Dict[str, Any]:
        return {"total_checks": self._checks}


__all__ = ["MCPSentry", "MCPRequest", "MCPResponse"]

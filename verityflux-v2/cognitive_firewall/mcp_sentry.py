from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List


@dataclass
class MCPRequest:
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    timestamp: datetime
    request_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse:
    allowed: bool
    risk_score: float
    reasoning: str
    violations: List[str] = field(default_factory=list)


class MCPSentry:
    def __init__(self):
        self.rules = []
        self._checks = 0

    def intercept(self, request: MCPRequest) -> MCPResponse:
        """Minimal policy check (allow all by default)."""
        self._checks += 1
        return MCPResponse(
            allowed=True,
            risk_score=0.0,
            reasoning="policy_allow",
            violations=[],
        )

    def inspect_context(self, context_data: dict) -> dict:
        # Placeholder logic to allow the UI to load
        return {"risk_score": 0, "status": "clean"}

    def get_statistics(self) -> Dict[str, Any]:
        return {"total_checks": self._checks}


__all__ = ["MCPSentry", "MCPRequest", "MCPResponse"]

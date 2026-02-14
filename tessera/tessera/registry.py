import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

@dataclass
class AgentIdentity:
    agent_id: str
    owner: str
    tenant_id: str = "default"
    status: str = 'active'
    allowed_tools: List[str] = field(default_factory=list)
    max_token_ttl: int = 3600
    risk_threshold: int = 50
    trust_score: float = 100.0
    trust_dependencies: List[str] = field(default_factory=list)
    status_reason: str = None
    last_updated: str = None
    metadata: Optional[Dict[str, Any]] = None

class TesseraRegistry:
    def __init__(self, registry_path: str = "data/tessera_registry.json"):
        self.registry_path = registry_path
        self.agents: Dict[str, AgentIdentity] = {}
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        self._load_registry()

    def _load_registry(self):
        if not os.path.exists(self.registry_path):
            self._create_default_registry()
            
        with open(self.registry_path, 'r') as f:
            data = json.load(f)
            for agent_id, config in data.items():
                # Filter config to only include fields defined in AgentIdentity dataclass
                valid_fields = {k: v for k, v in config.items() if k in AgentIdentity.__annotations__}
                self.agents[agent_id] = AgentIdentity(**valid_fields)

    def _create_default_registry(self):
        default_agents = {
            "agent_financial_bot_01": {
                "agent_id": "agent_financial_bot_01",
                "owner": "Finance_Dept",
                "status": "active",
                "allowed_tools": ["read_csv", "query_sql", "send_email"],
                "max_token_ttl": 3600,
                "risk_threshold": 70,
                "trust_score": 100.0,
                "trust_dependencies": []
            }
        }
        with open(self.registry_path, 'w') as f:
            json.dump(default_agents, f, indent=4)

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        return self.agents.get(agent_id)

    def list_agents(self, status: str = None) -> List[AgentIdentity]:
        if status:
            return [a for a in self.agents.values() if a.status == status]
        return list(self.agents.values())


class AgentRegistry(TesseraRegistry):
    """Compatibility alias for older documentation."""
    pass

    def degrade_trust(self, agent_id: str, amount: float, reason: str = None) -> bool:
        """Decrease an agent's trust score (floor at 0) and update timestamp."""
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        agent.trust_score = max(0.0, agent.trust_score - float(amount))
        agent.last_updated = datetime.utcnow().isoformat()
        if reason:
            agent.status_reason = reason
        return True

    def record_dependency_failure(self, agent_id: str, dependency_id: str, amount: float = 10.0) -> bool:
        """Degrade trust score if a dependency fails or becomes unsafe."""
        reason = f"Dependency {dependency_id} failed or unsafe"
        return self.degrade_trust(agent_id, amount, reason=reason)

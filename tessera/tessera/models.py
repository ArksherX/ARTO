from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    COMPROMISED = "compromised"
    BLACKLISTED = "blacklisted"


@dataclass
class AgentIdentityModel:
    agent_id: str
    owner: str
    status: AgentStatus = AgentStatus.ACTIVE
    allowed_tools: List[str] = field(default_factory=list)
    max_token_ttl: int = 3600
    risk_threshold: int = 50
    trust_score: float = 100.0
    trust_dependencies: List[str] = field(default_factory=list)
    status_reason: Optional[str] = None
    last_updated: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AccessDecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    FAIL_CLOSED = "fail_closed"

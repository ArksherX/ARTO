import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from pathlib import Path

from tessera.agent_keys import (
    generate_keypair,
    key_id_from_public,
    load_or_create_root_key,
    sign_public_key,
    sign_payload,
    verify_payload,
)

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
    # Optional runtime containment controls
    allowed_domains: List[str] = field(default_factory=list)
    allowed_path_prefixes: List[str] = field(default_factory=list)
    require_sandbox: bool = False
    agent_keys: List[Dict[str, Any]] = field(default_factory=list)
    active_key_id: Optional[str] = None
    allowed_delegates: List[str] = field(default_factory=list)
    allowed_roles: List[str] = field(default_factory=list)

class TesseraRegistry:
    def __init__(self, registry_path: str = "data/tessera_registry.json"):
        self.registry_path = registry_path
        self.agents: Dict[str, AgentIdentity] = {}
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        self.root_key_path = Path(os.getenv("TESSERA_ROOT_KEY_PATH", "data/tessera_root_key.json"))
        self.root_key = load_or_create_root_key(self.root_key_path)
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
        # Ensure keys exist for all loaded agents
        mutated = False
        for agent in self.agents.values():
            before = len(agent.agent_keys or [])
            self._ensure_agent_keys(agent)
            after = len(agent.agent_keys or [])
            if after != before:
                mutated = True
        if mutated:
            self._save_registry()

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

    def _save_registry(self):
        """Persist the in-memory registry to disk."""
        data = {}
        for agent_id, agent in self.agents.items():
            entry = {
                "agent_id": agent.agent_id,
                "owner": agent.owner,
                "tenant_id": agent.tenant_id,
                "status": agent.status,
                "allowed_tools": agent.allowed_tools,
                "max_token_ttl": agent.max_token_ttl,
                "risk_threshold": agent.risk_threshold,
                "trust_score": agent.trust_score,
                "trust_dependencies": agent.trust_dependencies,
                "metadata": agent.metadata,
                "allowed_domains": agent.allowed_domains,
                "allowed_path_prefixes": agent.allowed_path_prefixes,
                "require_sandbox": agent.require_sandbox,
                "agent_keys": agent.agent_keys,
                "active_key_id": agent.active_key_id,
                "allowed_delegates": agent.allowed_delegates,
                "allowed_roles": agent.allowed_roles,
            }
            if agent.status_reason:
                entry["status_reason"] = agent.status_reason
            if agent.last_updated:
                entry["last_updated"] = agent.last_updated
            data[agent_id] = entry
        with open(self.registry_path, 'w') as f:
            json.dump(data, f, indent=4)

    def register_agent(
        self,
        agent_id: str,
        owner: str,
        allowed_tools: List[str],
        tenant_id: str = "default",
        max_token_ttl: int = 3600,
        risk_threshold: int = 50,
        metadata: Optional[Dict[str, Any]] = None,
        allowed_domains: Optional[List[str]] = None,
        allowed_path_prefixes: Optional[List[str]] = None,
        require_sandbox: bool = False,
        public_key: Optional[str] = None,
        key_id: Optional[str] = None,
        issuer_signature: Optional[str] = None,
        allowed_delegates: Optional[List[str]] = None,
        allowed_roles: Optional[List[str]] = None,
    ) -> AgentIdentity:
        """Register a new agent or update an existing one. Returns the agent."""
        store_private = os.getenv("TESSERA_STORE_PRIVATE_KEYS", "true").lower() in ("1", "true", "yes")
        existing = self.agents.get(agent_id)
        if existing:
            # Update existing agent
            existing.owner = owner
            existing.allowed_tools = list(allowed_tools)
            existing.tenant_id = tenant_id
            existing.max_token_ttl = max_token_ttl
            existing.risk_threshold = risk_threshold
            existing.last_updated = datetime.utcnow().isoformat()
            if metadata is not None:
                existing.metadata = metadata
            if allowed_domains is not None:
                existing.allowed_domains = list(allowed_domains)
            if allowed_path_prefixes is not None:
                existing.allowed_path_prefixes = list(allowed_path_prefixes)
            existing.require_sandbox = bool(require_sandbox)
            if allowed_delegates is not None:
                existing.allowed_delegates = list(allowed_delegates)
            if allowed_roles is not None:
                existing.allowed_roles = list(allowed_roles)
            self._ensure_agent_keys(
                existing,
                public_key=public_key,
                key_id=key_id,
                issuer_signature=issuer_signature,
                store_private=store_private,
            )
            # Re-activate if it was blacklisted
            if existing.status == "blacklisted":
                existing.status = "active"
                existing.status_reason = "Re-registered"
            self._save_registry()
            return existing

        agent = AgentIdentity(
            agent_id=agent_id,
            owner=owner,
            tenant_id=tenant_id,
            status="active",
            allowed_tools=list(allowed_tools),
            max_token_ttl=max_token_ttl,
            risk_threshold=risk_threshold,
            trust_score=100.0,
            trust_dependencies=[],
            last_updated=datetime.now(timezone.utc).isoformat(),
            metadata=metadata,
            allowed_domains=list(allowed_domains or []),
            allowed_path_prefixes=list(allowed_path_prefixes or []),
            require_sandbox=bool(require_sandbox),
            allowed_delegates=list(allowed_delegates or []),
            allowed_roles=list(allowed_roles or []),
        )
        self._ensure_agent_keys(
            agent,
            public_key=public_key,
            key_id=key_id,
            issuer_signature=issuer_signature,
            store_private=store_private,
        )
        self.agents[agent_id] = agent
        self._save_registry()
        return agent

    def _ensure_agent_keys(
        self,
        agent: AgentIdentity,
        public_key: Optional[str] = None,
        key_id: Optional[str] = None,
        issuer_signature: Optional[str] = None,
        store_private: bool = True,
    ) -> None:
        if agent.agent_keys:
            if not agent.active_key_id:
                active = next((k for k in agent.agent_keys if k.get("status") == "active"), None)
                agent.active_key_id = active.get("key_id") if active else None
            return

        now = datetime.now(timezone.utc).isoformat()
        if public_key:
            kid = key_id or key_id_from_public(public_key)
            signature = issuer_signature or sign_public_key(self.root_key["private_key"], public_key)
            key_record = {
                "key_id": kid,
                "public_key": public_key,
                "issuer": self.root_key["key_id"],
                "issuer_signature": signature,
                "issued_at": now,
                "status": "active",
            }
            if store_private and agent.metadata and agent.metadata.get("private_key"):
                key_record["private_key"] = agent.metadata.get("private_key")
        else:
            kid, private_pem, public_pem = generate_keypair()
            signature = sign_public_key(self.root_key["private_key"], public_pem)
            key_record = {
                "key_id": kid,
                "public_key": public_pem,
                "issuer": self.root_key["key_id"],
                "issuer_signature": signature,
                "issued_at": now,
                "status": "active",
            }
            if store_private:
                key_record["private_key"] = private_pem
        agent.agent_keys = [key_record]
        agent.active_key_id = key_record["key_id"]

    def get_root_public_key(self) -> Dict[str, Any]:
        return {
            "key_id": self.root_key["key_id"],
            "public_key": self.root_key["public_key"],
            "created_at": self.root_key.get("created_at"),
        }

    def list_agent_keys(self, agent_id: str) -> Optional[Dict[str, Any]]:
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        keys = []
        for k in agent.agent_keys:
            entry = dict(k)
            entry.pop("private_key", None)
            keys.append(entry)
        return {"agent_id": agent_id, "active_key_id": agent.active_key_id, "keys": keys}

    def rotate_agent_key(self, agent_id: str) -> Optional[Dict[str, Any]]:
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        store_private = os.getenv("TESSERA_STORE_PRIVATE_KEYS", "true").lower() in ("1", "true", "yes")
        now = datetime.now(timezone.utc).isoformat()
        kid, private_pem, public_pem = generate_keypair()
        signature = sign_public_key(self.root_key["private_key"], public_pem)
        key_record = {
            "key_id": kid,
            "public_key": public_pem,
            "issuer": self.root_key["key_id"],
            "issuer_signature": signature,
            "issued_at": now,
            "status": "active",
        }
        if store_private:
            key_record["private_key"] = private_pem
        # Mark previous active as rotated
        for k in agent.agent_keys:
            if k.get("key_id") == agent.active_key_id and k.get("status") == "active":
                k["status"] = "rotated"
                k["rotated_at"] = now
        agent.agent_keys.append(key_record)
        agent.active_key_id = kid
        self._save_registry()
        return key_record

    def revoke_agent_key(self, agent_id: str, key_id: str, reason: str = None) -> bool:
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        now = datetime.now(timezone.utc).isoformat()
        for k in agent.agent_keys:
            if k.get("key_id") == key_id:
                k["status"] = "revoked"
                k["revoked_at"] = now
                if reason:
                    k["revocation_reason"] = reason
                if agent.active_key_id == key_id:
                    agent.active_key_id = None
                self._save_registry()
                return True
        return False

    def sign_action(self, agent_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        key = next((k for k in agent.agent_keys if k.get("key_id") == agent.active_key_id), None)
        if not key:
            return None
        private_key = key.get("private_key")
        if not private_key:
            return None
        signature = sign_payload(private_key, payload)
        return {"key_id": key.get("key_id"), "signature": signature}

    def verify_action_signature(
        self,
        agent_id: str,
        payload: Dict[str, Any],
        signature: str,
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        agent = self.agents.get(agent_id)
        if not agent:
            return {"valid": False, "reason": "agent_not_found"}
        key = None
        if key_id:
            key = next((k for k in agent.agent_keys if k.get("key_id") == key_id), None)
        else:
            key = next((k for k in agent.agent_keys if k.get("key_id") == agent.active_key_id), None)
        if not key:
            return {"valid": False, "reason": "key_not_found"}
        if key.get("status") == "revoked":
            return {"valid": False, "reason": "key_revoked"}
        valid = verify_payload(key.get("public_key", ""), payload, signature)
        return {
            "valid": valid,
            "reason": "ok" if valid else "signature_invalid",
            "key_id": key.get("key_id"),
        }

    def update_agent_status(self, agent_id: str, status: str, reason: str = None) -> Optional[AgentIdentity]:
        """Update an agent's status (active, suspended, blacklisted)."""
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        agent.status = status
        agent.last_updated = datetime.utcnow().isoformat()
        if reason:
            agent.status_reason = reason
        self._save_registry()
        return agent

    def delete_agent(self, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        if agent_id not in self.agents:
            return False
        del self.agents[agent_id]
        self._save_registry()
        return True

    def degrade_trust(self, agent_id: str, amount: float, reason: str = None) -> bool:
        """Decrease an agent's trust score (floor at 0) and update timestamp."""
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        agent.trust_score = max(0.0, agent.trust_score - float(amount))
        agent.last_updated = datetime.utcnow().isoformat()
        if reason:
            agent.status_reason = reason
        self._save_registry()
        return True

    def record_dependency_failure(self, agent_id: str, dependency_id: str, amount: float = 10.0) -> bool:
        """Degrade trust score if a dependency fails or becomes unsafe."""
        reason = f"Dependency {dependency_id} failed or unsafe"
        return self.degrade_trust(agent_id, amount, reason=reason)


class AgentRegistry(TesseraRegistry):
    """Compatibility alias for older documentation."""
    pass

"""
Tessera Gatekeeper - Token Validation Middleware
"""
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from urllib.parse import urlparse

from tessera.token_generator import TokenGenerator
from tessera.revocation import RevocationList
from tessera.registry import TesseraRegistry
from tessera.token_replay_cache import TokenReplayCache

class AccessDecision(Enum):
    """Access control decision"""
    ALLOW = "allow"
    DENY_NO_TOKEN = "deny_no_token"
    DENY_INVALID_TOKEN = "deny_invalid_token"
    DENY_EXPIRED = "deny_expired"
    DENY_REVOKED = "deny_revoked"
    DENY_SCOPE_MISMATCH = "deny_scope_mismatch"
    DENY_DPOP_INVALID = "deny_dpop_invalid"
    DENY_DEPENDENCY_RISK = "deny_dependency_risk"
    DENY_REPLAY = "deny_replay"
    DENY_DELEGATION_EXCEEDED = "deny_delegation_exceeded"
    DENY_EGRESS_POLICY = "deny_egress_policy"
    DENY_CONTAINMENT_POLICY = "deny_containment_policy"

@dataclass
class GatekeeperResult:
    """Result of gatekeeper validation"""
    decision: AccessDecision
    agent_id: Optional[str] = None
    tool: Optional[str] = None
    risk_threshold: Optional[int] = None
    payload: Optional[Dict] = None
    reason: str = ""

class Gatekeeper:
    """Validates Tessera tokens and enforces access control"""
    
    MAX_DELEGATION_DEPTH = 5

    def __init__(
        self,
        token_generator: TokenGenerator,
        revocation_list: RevocationList,
        registry: Optional[TesseraRegistry] = None
    ):
        self.token_generator = token_generator
        self.revocation_list = revocation_list
        self.registry = registry or getattr(token_generator, "registry", None)
        self.replay_cache = TokenReplayCache()
    
    def validate_access(
        self, 
        token: str, 
        requested_tool: str,
        dpop_proof: Optional[str] = None,
        expected_htm: Optional[str] = None,
        expected_htu: Optional[str] = None,
        target_url: Optional[str] = None,
        file_path: Optional[str] = None,
        sandbox_attested: Optional[bool] = None,
    ) -> GatekeeperResult:
        """Validate agent access to a tool"""
        # Validate token
        payload = self.token_generator.validate_token(token)
        
        if not payload:
            return GatekeeperResult(
                decision=AccessDecision.DENY_INVALID_TOKEN,
                reason="Token is invalid or expired"
            )
        
        # Check revocation
        jti = payload.get('jti')
        if self.revocation_list.is_revoked(jti):
            return GatekeeperResult(
                decision=AccessDecision.DENY_REVOKED,
                agent_id=payload.get('sub'),
                reason="Token has been revoked"
            )

        # DPoP verification (if required or provided)
        cnf = payload.get("cnf") or {}
        jkt = cnf.get("jkt")
        if self.token_generator.require_dpop or dpop_proof:
            if not (jkt and dpop_proof):
                return GatekeeperResult(
                    decision=AccessDecision.DENY_DPOP_INVALID,
                    agent_id=payload.get('sub'),
                    reason="Missing DPoP proof or thumbprint"
                )
            if not self.token_generator.validate_dpop_proof(
                dpop_proof,
                required_jkt=jkt,
                expected_htm=expected_htm,
                expected_htu=expected_htu
            ):
                return GatekeeperResult(
                    decision=AccessDecision.DENY_DPOP_INVALID,
                    agent_id=payload.get('sub'),
                    reason="Invalid DPoP proof"
                )
        
        # Delegation chain validation
        delegation_depth = payload.get('delegation_depth', 0)
        if delegation_depth > self.MAX_DELEGATION_DEPTH:
            return GatekeeperResult(
                decision=AccessDecision.DENY_DELEGATION_EXCEEDED,
                agent_id=payload.get('sub'),
                reason=f"Delegation depth {delegation_depth} exceeds max {self.MAX_DELEGATION_DEPTH}"
            )

        delegation_chain = payload.get('delegation_chain')
        if delegation_chain:
            # Validate scope intersection through the chain
            prev_scopes = None
            for link in delegation_chain:
                link_scopes = set(link.get('scopes_granted', []))
                if prev_scopes is not None and link_scopes:
                    if not link_scopes.issubset(prev_scopes):
                        return GatekeeperResult(
                            decision=AccessDecision.DENY_DELEGATION_EXCEEDED,
                            agent_id=payload.get('sub'),
                            reason="Delegation chain scope escalation detected"
                        )
                prev_scopes = link_scopes

        # Verify scope
        token_tool = payload.get('tool')
        if token_tool != requested_tool:
            return GatekeeperResult(
                decision=AccessDecision.DENY_SCOPE_MISMATCH,
                agent_id=payload.get('sub'),
                tool=requested_tool,
                reason=f"Token grants access to '{token_tool}', not '{requested_tool}'"
            )

        # Nonce-based replay prevention (if nonce present)
        nonce = payload.get("nonce")
        if nonce:
            exp = payload.get("exp")
            now = int(datetime.utcnow().timestamp())
            ttl_seconds = max(1, int(exp - now)) if exp else 60
            if not self.replay_cache.check_and_store(nonce, ttl_seconds=ttl_seconds):
                return GatekeeperResult(
                    decision=AccessDecision.DENY_REPLAY,
                    agent_id=payload.get('sub'),
                    reason="Token replay detected"
                )

        # Dependency trust check (degrade trust if dependency fails)
        if self.registry:
            agent = self.registry.get_agent(payload.get('sub'))
            if agent:
                # Runtime containment: egress allowlist
                if target_url and getattr(agent, "allowed_domains", None):
                    try:
                        host = (urlparse(target_url).hostname or "").lower()
                    except Exception:
                        host = ""
                    allowed = [d.lower().strip() for d in (agent.allowed_domains or []) if d]
                    if host and allowed and host not in allowed:
                        return GatekeeperResult(
                            decision=AccessDecision.DENY_EGRESS_POLICY,
                            agent_id=agent.agent_id,
                            reason=f"Egress host '{host}' not in agent allowlist",
                        )

                # Runtime containment: file path prefix allowlist
                if file_path and getattr(agent, "allowed_path_prefixes", None):
                    prefixes = [p for p in (agent.allowed_path_prefixes or []) if p]
                    if prefixes and not any(str(file_path).startswith(p) for p in prefixes):
                        return GatekeeperResult(
                            decision=AccessDecision.DENY_CONTAINMENT_POLICY,
                            agent_id=agent.agent_id,
                            reason=f"File path '{file_path}' outside allowed prefixes",
                        )

                # Runtime containment: sandbox attestation requirement
                if bool(getattr(agent, "require_sandbox", False)) and not bool(sandbox_attested):
                    return GatekeeperResult(
                        decision=AccessDecision.DENY_CONTAINMENT_POLICY,
                        agent_id=agent.agent_id,
                        reason="Agent requires sandboxed execution attestation",
                    )

                for dependency_id in (agent.trust_dependencies or []):
                    dependency = self.registry.get_agent(dependency_id)
                    if not dependency or dependency.status != "active" or dependency.trust_score < 50:
                        self.registry.record_dependency_failure(agent.agent_id, dependency_id, amount=10.0)
                        return GatekeeperResult(
                            decision=AccessDecision.DENY_DEPENDENCY_RISK,
                            agent_id=agent.agent_id,
                            reason=f"Dependency {dependency_id} failed or unsafe"
                        )
        
        # Allow
        return GatekeeperResult(
            decision=AccessDecision.ALLOW,
            agent_id=payload.get('sub'),
            tool=requested_tool,
            risk_threshold=payload.get('risk_threshold'),
            payload=payload,
            reason="Access granted"
        )

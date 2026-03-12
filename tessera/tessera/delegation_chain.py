#!/usr/bin/env python3
"""
Delegation Chain - Inter-Agent Identity Handoff

Enables parent agents to delegate scoped, short-lived tokens to sub-agents.
Scopes can only be narrowed (never escalated) through the chain.
Every link in the chain is validated to ensure integrity.
"""

import secrets
from dataclasses import dataclass, field
from typing import List, Set, Dict, Any, Optional
from datetime import datetime, UTC


@dataclass
class DelegatedToken:
    """A delegated token with chain of custody"""
    token: str
    delegation_chain: List[Dict[str, Any]]
    effective_scopes: Set[str]
    depth: int
    parent_jti: str
    jti: str
    delegated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class DelegationValidationResult:
    """Result of validating a delegation chain"""
    valid: bool
    reason: str
    chain_depth: int = 0
    effective_scopes: Set[str] = field(default_factory=set)
    violations: List[str] = field(default_factory=list)


class DelegationChain:
    """
    Inter-agent identity delegation with scope narrowing.

    When a parent agent needs to delegate work to a sub-agent, it creates
    a delegated token that:
    - Has scopes that are a SUBSET of the parent's (never escalate)
    - Includes the full chain: [original_user, parent_agent, sub_agent]
    - Has a configurable max depth (default 5)
    - Can be validated at every link
    """

    def __init__(self, max_depth: int = 5, token_generator=None):
        self.max_depth = max_depth
        self.token_generator = token_generator
        self._delegations: Dict[str, DelegatedToken] = {}

    def create_delegated_token(
        self,
        parent_token: Dict[str, Any],
        sub_agent_id: str,
        requested_scopes: Set[str],
    ) -> Optional[DelegatedToken]:
        """
        Create a delegated token for a sub-agent.

        Args:
            parent_token: Decoded JWT payload of the parent token
            sub_agent_id: Agent receiving the delegation
            requested_scopes: Scopes requested by the sub-agent

        Returns:
            DelegatedToken if delegation is valid, None otherwise
        """
        # Extract parent info
        parent_id = parent_token.get("sub", "unknown")
        parent_scopes = set(parent_token.get("scopes", []))
        parent_jti = parent_token.get("jti", "unknown")
        existing_chain = parent_token.get("delegation_chain", [])
        current_depth = parent_token.get("delegation_depth", 0)

        # If parent has no explicit scopes, derive least-privilege scopes from tool
        if not parent_scopes:
            tool = parent_token.get("tool", "")
            if tool:
                parent_scopes = self._derive_scopes_from_tool(tool)

        # Check depth limit
        if current_depth >= self.max_depth:
            return None

        # Enforce scope narrowing: requested scopes MUST be subset of parent scopes
        effective_scopes = requested_scopes & parent_scopes
        if not effective_scopes:
            return None

        # Build delegation chain
        chain_entry = {
            "agent_id": parent_id,
            "jti": parent_jti,
            "delegated_to": sub_agent_id,
            "scopes_granted": list(effective_scopes),
            "timestamp": datetime.now(UTC).isoformat(),
        }
        new_chain = existing_chain + [chain_entry]

        # Generate delegated token ID
        jti = f"deleg_{secrets.token_hex(16)}"

        delegated = DelegatedToken(
            token=jti,  # In production, this would be a signed JWT
            delegation_chain=new_chain,
            effective_scopes=effective_scopes,
            depth=current_depth + 1,
            parent_jti=parent_jti,
            jti=jti,
        )

        self._delegations[jti] = delegated
        return delegated

    def _derive_scopes_from_tool(self, tool_name: str) -> Set[str]:
        """
        Derive coarse scopes from tool name when token has no explicit scopes.

        This prevents accidental privilege expansion (e.g. treating a tool name
        as an arbitrary scope) and preserves strict narrowing behavior.
        """
        t = (tool_name or "").lower()
        scopes: Set[str] = set()
        if any(k in t for k in ("read", "view", "list", "query", "fetch", "get")):
            scopes.add("read")
        if any(k in t for k in ("write", "update", "create", "edit", "modify", "save")):
            scopes.add("write")
        if any(k in t for k in ("delete", "drop", "admin", "root", "sudo", "grant")):
            scopes.add("admin")
        # Unknown tool defaults to read-only to avoid escalations.
        return scopes or {"read"}

    def validate_delegation(
        self, token: Dict[str, Any]
    ) -> DelegationValidationResult:
        """
        Validate every link in a delegation chain.

        Checks:
        - Chain depth doesn't exceed max
        - Scopes only narrow (never escalate) at each link
        - All links are present and well-formed
        """
        chain = token.get("delegation_chain", [])
        depth = token.get("delegation_depth", len(chain))
        violations = []

        # Check depth
        if depth > self.max_depth:
            violations.append(
                f"Delegation depth {depth} exceeds max {self.max_depth}"
            )

        # Validate each link
        prev_scopes = None
        for i, link in enumerate(chain):
            link_scopes = set(link.get("scopes_granted", []))

            # Required fields
            for req_field in ["agent_id", "delegated_to", "scopes_granted"]:
                if req_field not in link:
                    violations.append(f"Link {i}: missing field '{req_field}'")

            # Scope narrowing check
            if prev_scopes is not None and link_scopes:
                if not link_scopes.issubset(prev_scopes):
                    escalated = link_scopes - prev_scopes
                    violations.append(
                        f"Link {i}: scope escalation detected - "
                        f"new scopes {list(escalated)} not in parent"
                    )

            prev_scopes = link_scopes

        # Calculate effective scopes (intersection of all links)
        effective_scopes = self.get_effective_scopes(token)

        return DelegationValidationResult(
            valid=len(violations) == 0,
            reason="Delegation chain valid" if not violations else "; ".join(violations),
            chain_depth=depth,
            effective_scopes=effective_scopes,
            violations=violations,
        )

    def get_effective_scopes(self, token: Dict[str, Any]) -> Set[str]:
        """
        Calculate effective scopes: intersection of all scopes in the chain.

        The effective scopes are the most restrictive set - the intersection
        of every link's granted scopes.
        """
        chain = token.get("delegation_chain", [])
        if not chain:
            return set(token.get("scopes", []))

        # Start with first link's scopes
        effective = set(chain[0].get("scopes_granted", []))

        # Intersect with each subsequent link
        for link in chain[1:]:
            link_scopes = set(link.get("scopes_granted", []))
            effective = effective & link_scopes

        return effective

    def get_delegation(self, jti: str) -> Optional[DelegatedToken]:
        return self._delegations.get(jti)

    def revoke_delegation(self, jti: str) -> bool:
        if jti in self._delegations:
            del self._delegations[jti]
            return True
        return False


__all__ = ["DelegationChain", "DelegatedToken", "DelegationValidationResult"]

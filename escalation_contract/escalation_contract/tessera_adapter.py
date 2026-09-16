"""
Wiring escalation_contract to Tessera's real RevocationList -- the concrete
"consequence" half of the design.

This module is the only place in this package that imports Tessera. It
exists so the core contract.py stays dependency-free and independently
testable, while this adapter proves the design actually connects to
working enforcement: Tessera's Gatekeeper.validate_access() already checks
RevocationList.is_revoked(jti) on every request (gatekeeper.py:79), so a
revocation triggered here is real and immediate, not a new code path that
still needs its own separate enforcement wiring.
"""

from __future__ import annotations

from typing import Optional

from .contract import EscalationContract, EscalationContractStore


def make_tessera_revoking_store(
    revocation_list,  # tessera.revocation.RevocationList -- typed loosely so
                       # this module doesn't hard-import tessera at module
                       # load time; see revoking_on_expire() below.
    ttl_seconds: Optional[int] = None,
) -> EscalationContractStore:
    """
    Build an EscalationContractStore whose on_expire callback revokes the
    contract's subject_token (the token's jti) via a real Tessera
    RevocationList.

    Args:
        revocation_list: a tessera.revocation.RevocationList instance (or
            anything exposing the same .revoke(jti, reason=..., ttl=...)
            method -- duck-typed deliberately, so a test double works
            without needing Tessera installed).
        ttl_seconds: forwarded to RevocationList.revoke()'s ttl parameter;
            None uses RevocationList's own default (7 days).

    Returns:
        EscalationContractStore configured to revoke on expiry. A contract
        opened without a subject_token is expired without any revocation
        call -- there's nothing to revoke, and that's a legitimate use
        (a finding that needs human attention but doesn't gate a specific
        credential).
    """

    def revoking_on_expire(contract: EscalationContract) -> None:
        if not contract.subject_token:
            return
        revocation_list.revoke(
            contract.subject_token,
            reason=f"unacknowledged escalation contract expired: {contract.reason}",
            ttl=ttl_seconds,
        )

    return EscalationContractStore(on_expire=revoking_on_expire)


__all__ = ["make_tessera_revoking_store"]

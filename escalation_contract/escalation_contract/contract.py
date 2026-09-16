"""
Escalation contracts: a finding that requires a bound, owned response, not
just a log line.

This is Issue 18's argument -- a control that only observes and records
isn't a control, because nobody is required to act on what it observes --
turned into working code. VerityFlux (or any detector) already tells you
*that* something escalated. This module answers the next question, the one
frontier-lab embedded evaluators currently can't: if nobody acknowledges
it in time, what actually happens?

The answer here is deliberately narrow and mechanical: a contract has a
deadline. If nobody acknowledges it before the deadline, sweeping it
triggers a caller-supplied consequence function -- in production, that
function is Tessera's existing RevocationList.revoke(), which every real
request already passes through Gatekeeper.validate_access(). The
enforcement isn't new; what's new is that a finding is now guaranteed to
either get a named human answer or a real consequence, not a third
option where it just sits in a log.

This module has zero dependency on Tessera (or any other Tessera-adjacent
package) so it stays testable and reusable on its own -- see
escalation_contract.tessera_adapter for the concrete wiring to Tessera's
RevocationList.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional


class ContractStatus(str, Enum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    EXPIRED = "expired"


class ContractAlreadyResolvedError(Exception):
    """Raised when acknowledging a contract that's already been acknowledged or expired."""


class ContractExpiredError(Exception):
    """Raised when attempting to acknowledge a contract past its deadline."""


class ContractNotFoundError(Exception):
    """Raised when a contract_id doesn't exist in the store."""


@dataclass
class EscalationContract:
    """One finding that requires an owned response before a deadline."""

    contract_id: str
    agent_id: str
    reason: str
    opened_at: datetime
    deadline: datetime
    status: ContractStatus = ContractStatus.PENDING
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    # Opaque token identifying the credential/session this contract gates --
    # what a consequence function acts on if the deadline lapses. Kept
    # generic (not "jti") so this module isn't Tessera-specific.
    subject_token: Optional[str] = None


class EscalationContractStore:
    """
    In-memory contract store. One instance per process is enough for a
    single VerityFlux/Tessera deployment; a persistent backend (Redis, a
    table) is a drop-in replacement for the same interface if a deployment
    needs contracts to survive a restart -- not built here, since nothing
    in this research so far has needed that yet, and building it
    speculatively would be exactly the kind of premature scope this
    project's own discipline argues against.
    """

    def __init__(self, on_expire: Optional[Callable[[EscalationContract], None]] = None):
        """
        Args:
            on_expire: called once, synchronously, for each contract that
                sweep_expired() finds past its deadline and still pending.
                In production this is the function that actually revokes
                the subject_token -- see tessera_adapter.py for the real
                wiring. Left as a plain callback here so this module never
                needs to import Tessera (or anything else) to be useful.
        """
        self._contracts: Dict[str, EscalationContract] = {}
        self._on_expire = on_expire

    def open(
        self,
        *,
        agent_id: str,
        reason: str,
        window_seconds: float,
        subject_token: Optional[str] = None,
    ) -> EscalationContract:
        """Open a new pending contract with a deadline window_seconds from now."""
        now = datetime.now(timezone.utc)
        contract = EscalationContract(
            contract_id=str(uuid.uuid4()),
            agent_id=agent_id,
            reason=reason,
            opened_at=now,
            deadline=now + timedelta(seconds=window_seconds),
            subject_token=subject_token,
        )
        self._contracts[contract.contract_id] = contract
        return contract

    def acknowledge(self, contract_id: str, *, acknowledged_by: str) -> EscalationContract:
        """
        Record that a named, accountable identity acknowledged the finding.

        Raises:
            ContractNotFoundError: no such contract.
            ContractAlreadyResolvedError: already acknowledged or already
                swept as expired.
            ContractExpiredError: the deadline has passed but sweep_expired()
                hasn't run yet -- acknowledgment is refused rather than
                silently accepted, because the deadline is the actual
                contract; a late sweep shouldn't grant a grace period the
                design didn't promise.
        """
        contract = self._contracts.get(contract_id)
        if contract is None:
            raise ContractNotFoundError(contract_id)
        if contract.status != ContractStatus.PENDING:
            raise ContractAlreadyResolvedError(
                f"contract {contract_id} is already {contract.status.value}"
            )
        if datetime.now(timezone.utc) >= contract.deadline:
            raise ContractExpiredError(
                f"contract {contract_id}'s deadline has passed; it will be (or was) swept as expired"
            )

        contract.status = ContractStatus.ACKNOWLEDGED
        contract.acknowledged_by = acknowledged_by
        contract.acknowledged_at = datetime.now(timezone.utc)
        return contract

    def sweep_expired(self) -> List[EscalationContract]:
        """
        Mark every still-pending contract past its deadline as EXPIRED, and
        invoke on_expire for each one. Call this periodically (a scheduler,
        a cron, a background task) -- it does not run itself.

        Returns the list of contracts that were just expired by this call
        (not ones already expired by a previous sweep).
        """
        now = datetime.now(timezone.utc)
        newly_expired = []
        for contract in self._contracts.values():
            if contract.status == ContractStatus.PENDING and now >= contract.deadline:
                contract.status = ContractStatus.EXPIRED
                newly_expired.append(contract)

        for contract in newly_expired:
            if self._on_expire is not None:
                self._on_expire(contract)

        return newly_expired

    def get(self, contract_id: str) -> Optional[EscalationContract]:
        return self._contracts.get(contract_id)

    def pending_for_agent(self, agent_id: str) -> List[EscalationContract]:
        return [
            c
            for c in self._contracts.values()
            if c.agent_id == agent_id and c.status == ContractStatus.PENDING
        ]


__all__ = [
    "ContractStatus",
    "EscalationContract",
    "EscalationContractStore",
    "ContractAlreadyResolvedError",
    "ContractExpiredError",
    "ContractNotFoundError",
]

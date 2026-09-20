"""Report-only escalation store — Stage 1 of the enforcement rollout.

Opens real contracts with real deadlines, and when one lapses unacknowledged
it records what *would* have happened instead of doing it. Nothing is revoked
and no traffic is affected.

Why this stage exists at all:

Escalation contracts are only worth enabling if the underlying detector is
right often enough. The current honest figure is roughly 44% pre-critical
detection at an ~8% false-positive rate, measured on a natural-language
corpus -- so about one flagged session in twelve is a false alarm. Wiring
revocation straight to that would cut off a working agent one time in twelve,
and a security control that breaks working systems gets switched off.

Stage 1 turns that benchmark number into an observed number on real traffic,
at zero risk. Its output is the evidence that decides whether Stage 3
(actual revocation) is ever safe to enable, and for whom.

Stages:
    1. report_only   -- contracts open, expiry logged, nothing revoked  (this module)
    2. acknowledge   -- contracts must be acknowledged, still no revocation
    3. revoking      -- expiry revokes the subject credential
                        (escalation_contract.tessera_adapter)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .contract import EscalationContract, EscalationContractStore

logger = logging.getLogger(__name__)


@dataclass
class WouldHaveRevoked:
    """One contract that lapsed unacknowledged, recorded rather than acted on."""

    contract_id: str
    agent_id: str
    reason: str
    subject_token: Optional[str]
    opened_at: datetime
    deadline: datetime
    observed_at: datetime


@dataclass
class ReportOnlyLedger:
    """In-memory record of what Stage 3 would have done.

    Deliberately simple and process-local. The point of Stage 1 is to produce a
    rate, not to be a durable audit store -- Vestigia is where durable evidence
    belongs, and wiring that is a separate decision.
    """

    opened: int = 0
    acknowledged: int = 0
    would_have_revoked: List[WouldHaveRevoked] = field(default_factory=list)

    @property
    def lapsed(self) -> int:
        return len(self.would_have_revoked)

    def summary(self) -> dict:
        """Counts suitable for logging or a metrics endpoint."""
        resolved = self.acknowledged + self.lapsed
        return {
            "contracts_opened": self.opened,
            "contracts_acknowledged": self.acknowledged,
            "contracts_lapsed": self.lapsed,
            # Share of resolved contracts a human actually answered. Low values
            # mean nobody is watching the queue, which is what Stage 2 exists
            # to surface -- a deadline nobody reads is a delayed outage.
            "acknowledgement_rate": (self.acknowledged / resolved) if resolved else None,
        }


def make_report_only_store(ledger: Optional[ReportOnlyLedger] = None):
    """Build a Stage 1 store plus the ledger recording what it would have done.

    Returns (store, ledger). The store behaves exactly like a live one --
    contracts open, deadlines apply, acknowledgement works -- except that a
    lapsed deadline is recorded instead of revoking anything.
    """
    ledger = ledger if ledger is not None else ReportOnlyLedger()

    def on_expire(contract: EscalationContract) -> None:
        entry = WouldHaveRevoked(
            contract_id=contract.contract_id,
            agent_id=contract.agent_id,
            reason=contract.reason,
            subject_token=contract.subject_token,
            opened_at=contract.opened_at,
            deadline=contract.deadline,
            observed_at=datetime.now(timezone.utc),
        )
        ledger.would_have_revoked.append(entry)
        logger.warning(
            "[escalation:report-only] WOULD HAVE REVOKED agent=%s token=%s "
            "contract=%s reason=%r deadline=%s — no action taken (Stage 1)",
            contract.agent_id,
            contract.subject_token or "<none>",
            contract.contract_id,
            contract.reason,
            contract.deadline.isoformat(),
        )

    store = EscalationContractStore(on_expire=on_expire)

    # Count opens and acknowledgements without subclassing, so the store stays
    # the real implementation rather than a lookalike that could drift from it.
    real_open = store.open
    real_ack = store.acknowledge

    def counting_open(**kwargs):
        contract = real_open(**kwargs)
        ledger.opened += 1
        logger.info(
            "[escalation:report-only] contract opened agent=%s deadline=%s",
            contract.agent_id,
            contract.deadline.isoformat(),
        )
        return contract

    def counting_acknowledge(contract_id: str, **kwargs):
        contract = real_ack(contract_id, **kwargs)
        ledger.acknowledged += 1
        return contract

    store.open = counting_open          # type: ignore[method-assign]
    store.acknowledge = counting_acknowledge  # type: ignore[method-assign]
    return store, ledger

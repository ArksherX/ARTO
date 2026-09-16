import time
from datetime import timedelta

import pytest

from escalation_contract import (
    ContractAlreadyResolvedError,
    ContractExpiredError,
    ContractNotFoundError,
    ContractStatus,
    EscalationContractStore,
)


def test_open_creates_pending_contract():
    store = EscalationContractStore()
    contract = store.open(agent_id="agent-1", reason="turning point flagged", window_seconds=60)
    assert contract.status == ContractStatus.PENDING
    assert contract.agent_id == "agent-1"
    assert contract.deadline > contract.opened_at


def test_acknowledge_before_deadline_succeeds():
    store = EscalationContractStore()
    contract = store.open(agent_id="agent-1", reason="x", window_seconds=60)
    acked = store.acknowledge(contract.contract_id, acknowledged_by="alice@example.com")
    assert acked.status == ContractStatus.ACKNOWLEDGED
    assert acked.acknowledged_by == "alice@example.com"
    assert acked.acknowledged_at is not None


def test_acknowledge_unknown_contract_raises():
    store = EscalationContractStore()
    with pytest.raises(ContractNotFoundError):
        store.acknowledge("does-not-exist", acknowledged_by="alice")


def test_acknowledge_twice_raises():
    store = EscalationContractStore()
    contract = store.open(agent_id="agent-1", reason="x", window_seconds=60)
    store.acknowledge(contract.contract_id, acknowledged_by="alice")
    with pytest.raises(ContractAlreadyResolvedError):
        store.acknowledge(contract.contract_id, acknowledged_by="bob")


def test_acknowledge_past_deadline_raises_without_sweep():
    """The deadline itself is the contract -- acknowledgment is refused the
    instant it passes, not only after sweep_expired() happens to run."""
    store = EscalationContractStore()
    contract = store.open(agent_id="agent-1", reason="x", window_seconds=0.01)
    time.sleep(0.02)
    with pytest.raises(ContractExpiredError):
        store.acknowledge(contract.contract_id, acknowledged_by="alice")


def test_sweep_expired_marks_and_returns_only_newly_expired():
    store = EscalationContractStore()
    fast = store.open(agent_id="agent-1", reason="x", window_seconds=0.01)
    slow = store.open(agent_id="agent-1", reason="y", window_seconds=60)
    time.sleep(0.02)

    expired = store.sweep_expired()
    assert [c.contract_id for c in expired] == [fast.contract_id]
    assert store.get(fast.contract_id).status == ContractStatus.EXPIRED
    assert store.get(slow.contract_id).status == ContractStatus.PENDING

    # A second sweep with nothing newly expired returns nothing (not the
    # same contract again).
    assert store.sweep_expired() == []


def test_sweep_expired_invokes_on_expire_callback():
    calls = []
    store = EscalationContractStore(on_expire=lambda c: calls.append(c.contract_id))
    contract = store.open(agent_id="agent-1", reason="x", window_seconds=0.01, subject_token="jti-123")
    time.sleep(0.02)
    store.sweep_expired()
    assert calls == [contract.contract_id]


def test_acknowledged_contract_is_never_swept():
    store = EscalationContractStore()
    contract = store.open(agent_id="agent-1", reason="x", window_seconds=0.01)
    store.acknowledge(contract.contract_id, acknowledged_by="alice")
    time.sleep(0.02)
    expired = store.sweep_expired()
    assert expired == []
    assert store.get(contract.contract_id).status == ContractStatus.ACKNOWLEDGED


def test_pending_for_agent_excludes_resolved_contracts():
    store = EscalationContractStore()
    c1 = store.open(agent_id="agent-1", reason="a", window_seconds=60)
    c2 = store.open(agent_id="agent-1", reason="b", window_seconds=60)
    store.open(agent_id="agent-2", reason="c", window_seconds=60)  # different agent
    store.acknowledge(c2.contract_id, acknowledged_by="alice")

    pending = store.pending_for_agent("agent-1")
    assert [c.contract_id for c in pending] == [c1.contract_id]


def test_subject_token_is_carried_through_to_expired_contract():
    """The whole point: sweep must be able to tell the consequence function
    *which* credential to revoke."""
    seen_tokens = []
    store = EscalationContractStore(on_expire=lambda c: seen_tokens.append(c.subject_token))
    store.open(agent_id="agent-1", reason="x", window_seconds=0.01, subject_token="jti-abc")
    time.sleep(0.02)
    store.sweep_expired()
    assert seen_tokens == ["jti-abc"]

"""Stage 1 (report-only) escalation store.

The contract mechanism must behave exactly as it will in Stage 3 -- real
deadlines, real acknowledgement -- while never acting on a lapsed deadline.
These tests pin that distinction, because the whole value of Stage 1 is that
the numbers it produces are trustworthy predictions of what Stage 3 would do.
"""

import time

import pytest

from escalation_contract import (
    ContractStatus,
    ReportOnlyLedger,
    make_report_only_store,
)


def test_lapsed_contract_is_recorded_not_acted_on():
    store, ledger = make_report_only_store()
    store.open(agent_id="agent-a", reason="turning point", window_seconds=0.05,
               subject_token="jti-aaa")
    time.sleep(0.1)

    expired = store.sweep_expired()

    assert len(expired) == 1
    assert ledger.lapsed == 1
    recorded = ledger.would_have_revoked[0]
    assert recorded.agent_id == "agent-a"
    assert recorded.subject_token == "jti-aaa"


def test_acknowledged_contract_never_reaches_the_ledger():
    store, ledger = make_report_only_store()
    contract = store.open(agent_id="agent-b", reason="turning point", window_seconds=60)

    store.acknowledge(contract.contract_id, acknowledged_by="analyst@example.com")
    store.sweep_expired()

    assert ledger.acknowledged == 1
    assert ledger.lapsed == 0
    assert ledger.would_have_revoked == []


def test_deadlines_are_real_not_simulated():
    """Stage 1 must not shortcut expiry, or its rate would not predict Stage 3."""
    store, _ = make_report_only_store()
    contract = store.open(agent_id="agent-c", reason="turning point", window_seconds=60)

    assert store.sweep_expired() == []
    assert contract.status is ContractStatus.PENDING


def test_summary_reports_the_acknowledgement_rate():
    store, ledger = make_report_only_store()
    acked = store.open(agent_id="a", reason="r", window_seconds=60)
    store.acknowledge(acked.contract_id, acknowledged_by="analyst")
    store.open(agent_id="b", reason="r", window_seconds=0.05)
    store.open(agent_id="c", reason="r", window_seconds=0.05)
    time.sleep(0.1)
    store.sweep_expired()

    summary = ledger.summary()
    assert summary["contracts_opened"] == 3
    assert summary["contracts_acknowledged"] == 1
    assert summary["contracts_lapsed"] == 2
    # 1 acknowledged of 3 resolved — the signal that nobody is watching.
    assert summary["acknowledgement_rate"] == pytest.approx(1 / 3)


def test_summary_rate_is_none_before_anything_resolves():
    _, ledger = make_report_only_store()
    assert ledger.summary()["acknowledgement_rate"] is None


def test_caller_supplied_ledger_is_used():
    ledger = ReportOnlyLedger()
    store, returned = make_report_only_store(ledger)
    store.open(agent_id="a", reason="r", window_seconds=60)

    assert returned is ledger
    assert ledger.opened == 1

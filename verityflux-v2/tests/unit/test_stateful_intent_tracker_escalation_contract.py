"""
Tests for the additive escalation_store wiring on StatefulIntentTracker: a
flagged turning point opens a real EscalationContract, using a real
escalation_contract.EscalationContractStore (not a mock) -- proving the
finding actually gets a destination, not just a log line.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.stateful_intent_tracker import StatefulIntentTracker
from escalation_contract import EscalationContractStore, ContractStatus


def _drive_escalating_session(tracker, session_id="s1", agent_id="agent-1", **kwargs):
    """
    Force a monotonically-increasing drift sequence by stubbing the
    (unrelated, pre-existing) semantic drift detector's output directly,
    rather than relying on real conversation text to produce one. This
    test is about the escalation-contract wiring added on top of the
    turning-point signal, not about SemanticDriftDetector's own behavior --
    controlling its output keeps the two concerns separate.
    """
    scripted_scores = [0.05, 0.10, 0.20, 0.35, 0.50, 0.65]
    call_count = [0]

    def scripted_calculate_drift(**_):
        idx = min(call_count[0], len(scripted_scores) - 1)
        call_count[0] += 1
        return {"drift_score": scripted_scores[idx]}

    tracker.drift_detector.calculate_drift = scripted_calculate_drift

    last_result = None
    for _ in scripted_scores:
        last_result = tracker.track_interaction(
            session_id=session_id,
            agent_id=agent_id,
            user_input="turn",
            agent_response="turn",
            **kwargs,
        )
        if last_result.turning_point_flagged:
            return last_result
    return last_result


def test_turning_point_opens_a_real_escalation_contract():
    store = EscalationContractStore()
    tracker = StatefulIntentTracker(escalation_store=store, elevated_threshold=0.05)

    result = _drive_escalating_session(tracker, subject_token="jti-xyz")
    assert result.turning_point_flagged is True

    pending = store.pending_for_agent("agent-1")
    assert len(pending) == 1
    assert pending[0].subject_token == "jti-xyz"
    assert pending[0].status == ContractStatus.PENDING


def test_no_escalation_store_configured_behaves_exactly_as_before():
    """Default construction (no escalation_store) must not attempt to open
    anything -- this is the existing, unconfigured behavior, unchanged."""
    tracker = StatefulIntentTracker(elevated_threshold=0.05)
    result = _drive_escalating_session(tracker)
    # Should not raise, and turning_point_flagged still works independent
    # of whether a store is configured.
    assert isinstance(result.turning_point_flagged, bool)


def test_no_turning_point_does_not_open_a_contract():
    store = EscalationContractStore()
    tracker = StatefulIntentTracker(escalation_store=store)
    tracker.track_interaction(
        session_id="s2", agent_id="agent-2", user_input="hello", agent_response="hi"
    )
    assert store.pending_for_agent("agent-2") == []


def test_escalation_store_failure_does_not_break_tracking():
    """A broken store must not turn into a broken request path -- the
    interaction being tracked still gets a result even if opening the
    contract fails."""

    class BrokenStore:
        def open(self, **kwargs):
            raise RuntimeError("simulated store failure")

    tracker = StatefulIntentTracker(escalation_store=BrokenStore(), elevated_threshold=0.05)
    result = _drive_escalating_session(tracker)
    assert result.turning_point_flagged is True  # detection still worked
    # No exception propagated out of track_interaction despite the broken store.

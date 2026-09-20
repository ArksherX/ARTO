"""Trajectory escalation in the embedded firewall enforcement path.

Background: firewall.evaluate() scored each AgentAction in isolation. It
constructed self.intent_tracker and then never read it -- the attribute was
assigned twice and referenced nowhere else -- while still logging
"Stateful intent tracker initialized". The API verdict path (api/v2/main.py)
did fold trajectory state into its decision, so an embedded integration
received strictly weaker enforcement than an API one with nothing signalling
the difference.

That is the same single-turn blind spot reported upstream against garak
(NVIDIA #2173), AgentDojo (ETH #192) and PyRIT (Microsoft #2619): a control
that evaluates each turn independently cannot see escalation that only exists
across the sequence.

These tests pin the integration contract -- "when the tracker reports a
crescendo, escalate" -- rather than the tracker's own drift maths, which is
covered by the tracker's tests.
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.firewall import (
    AgentAction,
    CognitiveFirewall,
    FirewallAction,
    FirewallDecision,
)
from cognitive_firewall.stateful_intent_tracker import TrackingResult


class _StubTracker:
    """Returns a fixed verdict so the integration is tested deterministically."""

    def __init__(self, is_crescendo: bool):
        self._is_crescendo = is_crescendo
        self.calls = []

    def track_interaction(self, **kwargs):
        self.calls.append(kwargs)
        return TrackingResult(
            drift_score=0.91,
            drift_rate=0.22,
            is_crescendo=self._is_crescendo,
            explanation="drift accelerating across recent turns",
            alert_level="critical" if self._is_crescendo else "normal",
            turning_point_flagged=self._is_crescendo,
        )


class _ExplodingTracker:
    def track_interaction(self, **kwargs):
        raise RuntimeError("tracker unavailable")


def _firewall(tracker):
    # __new__ avoids the heavy constructor; only these two attributes are used.
    fw = CognitiveFirewall.__new__(CognitiveFirewall)
    fw.intent_tracker = tracker
    fw.logger = logging.getLogger("test.firewall")
    return fw


def _action(**context):
    ctx = {"session_id": "session-1"}
    ctx.update(context)
    return AgentAction(
        agent_id="agent-1",
        tool_name="file_read",
        parameters={"path": "/tmp/x"},
        reasoning_chain=["inspect the file"],
        original_goal="summarise the document",
        context=ctx,
    )


def _allow_decision(risk=10.0, action=FirewallAction.ALLOW):
    return FirewallDecision(
        action=action,
        confidence=0.9,
        reasoning="no single-action violation",
        risk_score=risk,
        violations=[],
        recommendations=[],
        context={},
    )


def test_crescendo_escalates_an_allow_to_require_approval():
    decision = _allow_decision()
    _firewall(_StubTracker(True))._apply_trajectory_escalation(_action(), decision, None)

    assert decision.action == FirewallAction.REQUIRE_APPROVAL
    assert decision.risk_score >= 80.0
    assert any("Multi-turn escalation" in v for v in decision.violations)


def test_no_crescendo_leaves_the_decision_alone():
    decision = _allow_decision()
    _firewall(_StubTracker(False))._apply_trajectory_escalation(_action(), decision, None)

    assert decision.action == FirewallAction.ALLOW
    assert decision.risk_score == 10.0
    # Drift is still reported even when it does not change the outcome.
    assert "session_drift" in decision.context


def test_trajectory_never_weakens_an_existing_block():
    decision = _allow_decision(risk=95.0, action=FirewallAction.BLOCK)
    _firewall(_StubTracker(True))._apply_trajectory_escalation(_action(), decision, None)

    assert decision.action == FirewallAction.BLOCK
    assert decision.risk_score == 95.0


def test_no_session_identity_is_a_no_op():
    """Without a session there is no correct trajectory to attribute this to.

    Inventing a per-call id makes every turn look like turn one; sharing one id
    merges unrelated conversations. Both are worse than not tracking.
    """
    tracker = _StubTracker(True)
    action = AgentAction(
        agent_id="agent-1",
        tool_name="file_read",
        parameters={},
        reasoning_chain=["step"],
        original_goal="goal",
        context={},
    )
    decision = _allow_decision()
    _firewall(tracker)._apply_trajectory_escalation(action, decision, None)

    assert tracker.calls == []
    assert decision.action == FirewallAction.ALLOW
    assert "session_drift" not in decision.context


def test_session_token_supplies_identity_when_context_does_not():
    tracker = _StubTracker(False)
    action = AgentAction(
        agent_id="agent-1",
        tool_name="file_read",
        parameters={},
        reasoning_chain=["step"],
        original_goal="goal",
        context={},
    )
    _firewall(tracker)._apply_trajectory_escalation(action, _allow_decision(), "token-abc")

    assert tracker.calls and tracker.calls[0]["session_id"] == "token-abc"


def test_tracker_failure_must_not_break_traffic():
    decision = _allow_decision()
    _firewall(_ExplodingTracker())._apply_trajectory_escalation(_action(), decision, None)

    assert decision.action == FirewallAction.ALLOW
    assert decision.risk_score == 10.0


def test_absent_tracker_is_a_no_op():
    decision = _allow_decision()
    _firewall(None)._apply_trajectory_escalation(_action(), decision, None)

    assert decision.action == FirewallAction.ALLOW

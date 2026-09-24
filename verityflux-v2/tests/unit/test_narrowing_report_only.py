"""NARROW Phase 1 — report-only parameter narrowing.

Phase 1 computes what clamping would do and records it. It must never change a
decision. The property under test is therefore as much about what does *not*
happen as what does: if this phase can alter an outcome, it is not a
measurement, and the rate it produces cannot be trusted to predict Phase 2.
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.narrowing import (
    ClampRule,
    NarrowingEvaluator,
    NarrowingLedger,
)


@pytest.fixture
def evaluator():
    return NarrowingEvaluator()


def test_value_over_a_numeric_bound_is_clampable(evaluator):
    outcome = evaluator.evaluate("query", {"limit": 5000})

    assert outcome.narrowable is True
    assert outcome.narrowed_parameters["limit"] == 1000
    assert outcome.original_parameters["limit"] == 5000


def test_value_within_bounds_is_not_a_candidate(evaluator):
    outcome = evaluator.evaluate("query", {"limit": 50})

    assert outcome.narrowable is False
    assert "no parameter exceeded" in outcome.declined_reason


def test_scope_narrowing_drops_only_disallowed_entries(evaluator):
    outcome = evaluator.evaluate("file_access", {"scope": ["read", "write", "delete"]})

    assert outcome.narrowable is True
    # Order preserved, only the disallowed entry removed.
    assert outcome.narrowed_parameters["scope"] == ["read", "write"]


def test_unknown_tool_is_never_narrowed(evaluator):
    """No rule means no narrowing. Inference is not a security control."""
    outcome = evaluator.evaluate("unknown_tool", {"limit": 999999})
    assert outcome.narrowable is False


def test_original_parameters_are_not_mutated(evaluator):
    """The evaluator proposes; it must not edit the caller's action."""
    params = {"limit": 5000}
    evaluator.evaluate("query", params)

    assert params == {"limit": 5000}


def test_booleans_are_not_treated_as_numbers(evaluator):
    """bool is a subclass of int; True must not be clamped as a quantity."""
    outcome = evaluator.evaluate("query", {"limit": True})
    assert outcome.narrowable is False


def test_clamped_value_keeps_its_type(evaluator):
    outcome = evaluator.evaluate("data_export", {"date_range_days": 365})
    assert outcome.narrowable is True
    assert isinstance(outcome.narrowed_parameters["date_range_days"], int)


def test_ledger_reports_the_narrowable_rate():
    ledger = NarrowingLedger()
    evaluator = NarrowingEvaluator()
    for tool, params in [
        ("query", {"limit": 5000}),          # narrowable
        ("query", {"limit": 5000}),          # narrowable
        ("query", {"limit": 5}),             # not
        ("send_email", {"to": "a@b.c"}),     # not
    ]:
        ledger.record(evaluator.evaluate(tool, params))

    summary = ledger.summary()
    assert summary["candidates_evaluated"] == 4
    assert summary["would_have_narrowed"] == 2
    assert summary["narrowable_rate"] == pytest.approx(0.5)


def test_ledger_rate_is_none_before_any_evaluation():
    assert NarrowingLedger().summary()["narrowable_rate"] is None


def test_ledger_examples_are_bounded():
    """A long-running process must not accumulate examples without limit."""
    ledger = NarrowingLedger(max_examples=3)
    evaluator = NarrowingEvaluator()
    for _ in range(10):
        ledger.record(evaluator.evaluate("query", {"limit": 5000}))

    assert ledger.would_have_narrowed == 10
    assert len(ledger.examples) == 3


def test_custom_rules_replace_the_defaults():
    rule = ClampRule(
        tool="t", parameter="p", description="capped at 5",
        violates=lambda v: v > 5, clamp=lambda v: 5,
    )
    evaluator = NarrowingEvaluator(rules=[rule])

    assert evaluator.evaluate("t", {"p": 9}).narrowed_parameters["p"] == 5
    # A default rule must no longer apply.
    assert evaluator.evaluate("query", {"limit": 5000}).narrowable is False


# ---------------------------------------------------------------------------
# The property that matters most: Phase 1 must not change any decision.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_firewall():
    """A fully-constructed firewall — real config, real detectors.

    Stubbing _evaluate_layers' dependencies would make the test about the stub
    rather than the property, so this uses the genuine object and varies only
    the evaluator.
    """
    from cognitive_firewall.firewall import CognitiveFirewall

    return CognitiveFirewall()


def _decide(firewall, action, monkeypatch, evaluator, ledger):
    """Run _evaluate_layers with narrowing configured as given, forcing the
    tier ladder to REQUIRE_APPROVAL so the narrowing block is reached.

    Default config scores these actions at zero risk, so the ladder never
    reaches REQUIRE_APPROVAL unaided; forcing it isolates the code under test
    instead of testing the detectors.
    """
    from cognitive_firewall.firewall import FirewallAction

    monkeypatch.setattr(firewall, "narrowing_evaluator", evaluator, raising=False)
    monkeypatch.setattr(firewall, "narrowing_ledger", ledger, raising=False)
    monkeypatch.setattr(
        firewall,
        "_make_tiered_decision",
        lambda *a, **k: (FirewallAction.REQUIRE_APPROVAL, "forced for test"),
        raising=False,
    )
    return firewall._evaluate_layers(action, None)


@pytest.fixture
def clampable_action():
    from cognitive_firewall.firewall import AgentAction

    return AgentAction(
        agent_id="a1",
        tool_name="query",
        parameters={"limit": 5000},
        reasoning_chain=["run the report"],
        original_goal="report",
    )


def test_phase1_records_without_changing_the_decision(
    real_firewall, clampable_action, monkeypatch
):
    """With and without the evaluator, the decision must be identical."""
    ledger = NarrowingLedger()

    enabled = _decide(real_firewall, clampable_action, monkeypatch, NarrowingEvaluator(), ledger)
    disabled = _decide(real_firewall, clampable_action, monkeypatch, None, None)

    assert enabled.action == disabled.action
    assert enabled.risk_score == disabled.risk_score
    assert enabled.violations == disabled.violations

    # …and the candidate was still recorded on the enabled path.
    assert ledger.would_have_narrowed == 1
    assert enabled.context["narrowing_candidate"]["enforced"] is False
    assert enabled.context["narrowing_candidate"]["narrowed_parameters"]["limit"] == 1000
    assert disabled.context.get("narrowing_candidate") is None


def test_evaluator_failure_cannot_affect_the_decision(
    real_firewall, clampable_action, monkeypatch
):
    """Measurement must never break traffic."""
    from cognitive_firewall.firewall import FirewallAction

    class Exploding:
        def evaluate(self, *a, **k):
            raise RuntimeError("evaluator broken")

    decision = _decide(
        real_firewall, clampable_action, monkeypatch, Exploding(), NarrowingLedger()
    )

    assert decision.action == FirewallAction.REQUIRE_APPROVAL
    assert "narrowing_candidate" not in decision.context


def test_allowed_actions_are_not_evaluated(real_firewall, clampable_action, monkeypatch):
    """Only REQUIRE_APPROVAL is a narrowing candidate.

    An action already permitted has nothing to gain from being reduced, and
    evaluating it would inflate the rate this phase exists to measure.
    """
    from cognitive_firewall.firewall import FirewallAction

    ledger = NarrowingLedger()
    monkeypatch.setattr(real_firewall, "narrowing_evaluator", NarrowingEvaluator(), raising=False)
    monkeypatch.setattr(real_firewall, "narrowing_ledger", ledger, raising=False)
    monkeypatch.setattr(
        real_firewall,
        "_make_tiered_decision",
        lambda *a, **k: (FirewallAction.ALLOW, "forced allow"),
        raising=False,
    )

    real_firewall._evaluate_layers(clampable_action, None)

    assert ledger.evaluated == 0

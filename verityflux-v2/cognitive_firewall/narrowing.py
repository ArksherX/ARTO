"""Parameter narrowing — Phase 1 (report-only).

NARROW is the missing middle in ARTO's decision vocabulary. Today a high-risk
action is either blocked or sent to a human; there is no outcome where it
proceeds in reduced form. With the detector near an 8% false-positive rate,
that means a false positive is always either a blocked working agent or a
human interrupted for nothing.

CAGE's GovernanceDecision.NARROW covers this case: an action that exceeds a
soft threshold but is not a hard violation gets its parameters clamped rather
than refused — semantics preserved, scope reduced.

**Phase 1 computes the narrowing and records it. It never changes a decision.**
The purpose is to find out how often NARROW would fire, and whether the clamps
look right, before anything executes differently. Same discipline as the
escalation-contract rollout: measure first, enforce later.

Design constraints, carried from the scope and deliberately strict:

- **Clamp, never transform.** A value is reduced within its own type and
  meaning. Rewriting a query, editing a prompt or substituting a tool is not
  narrowing — it is the system inventing an action nobody authorised.
- **Explicit rules only.** No inference. "The model guessed a safe value" is
  not a security control.
- **Never applies to hard blocks.** Callers must only consult this below the
  hard-block line; see the note in firewall._evaluate_layers.

KNOWN LIMIT — and a prerequisite for Phase 2:

The firewall records violations as free-text strings (`violations.append(
f"SQL: {description}")` and similar), so there is no mapping from a violation
back to the parameter that caused it. This module can therefore answer "does
this action have a parameter that exceeds a known soft bound?" but NOT "would
clamping it actually resolve the violation?"

For Phase 1 that is fine — the number being measured is how often a high-risk
action has something clampable at all. It is not fine for Phase 2: clamping
`limit` from 5000 to 1000 does nothing if the violation was "Deceptive intent
detected", and shipping a narrowed action that still violates would be worse
than blocking it. **Structured, parameter-attributed violations are a
prerequisite for enforcing NARROW**, and that work is not in this phase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ClampRule:
    """One declarative bound on one parameter of one tool.

    `clamp` receives the offending value and returns the reduced one. It must
    be total for values that fail `violates`, and must return a value of the
    same type and meaning.
    """

    tool: str
    parameter: str
    description: str
    violates: Callable[[Any], bool]
    clamp: Callable[[Any], Any]


def _max_numeric(limit: float) -> Tuple[Callable[[Any], bool], Callable[[Any], Any]]:
    def violates(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value > limit

    def clamp(value: Any) -> Any:
        return type(value)(limit) if isinstance(value, int) else limit

    return violates, clamp


def _subset_of(allowed: frozenset) -> Tuple[Callable[[Any], bool], Callable[[Any], Any]]:
    def violates(value: Any) -> bool:
        return isinstance(value, (list, tuple, set)) and not set(value) <= allowed

    def clamp(value: Any) -> Any:
        # Preserve input ordering; drop only what is not permitted.
        return [v for v in value if v in allowed]

    return violates, clamp


def _default_rules() -> List[ClampRule]:
    """A deliberately small starting registry.

    Phase 1 is a measurement exercise, so this covers a couple of obviously
    clampable shapes rather than attempting coverage. Breadth is Phase 3.
    """
    rules: List[ClampRule] = []

    v, c = _max_numeric(90)
    rules.append(ClampRule(
        tool="data_export", parameter="date_range_days",
        description="export window capped at 90 days", violates=v, clamp=c))

    v, c = _subset_of(frozenset({"read", "write"}))
    rules.append(ClampRule(
        tool="file_access", parameter="scope",
        description="destructive scopes removed, read/write retained",
        violates=v, clamp=c))

    v, c = _max_numeric(1000)
    rules.append(ClampRule(
        tool="query", parameter="limit",
        description="result set capped at 1000 rows", violates=v, clamp=c))

    return rules


@dataclass
class NarrowingOutcome:
    """What narrowing would have done to one action."""

    narrowable: bool
    original_parameters: Dict[str, Any] = field(default_factory=dict)
    narrowed_parameters: Dict[str, Any] = field(default_factory=dict)
    #: Human-readable description of each clamp that would have been applied.
    clamps_applied: List[str] = field(default_factory=list)
    #: Why narrowing was declined, when it was.
    declined_reason: Optional[str] = None


@dataclass
class NarrowingLedger:
    """Phase 1 record of what NARROW would have done.

    Process-local and intentionally simple — the point is a rate, not durable
    evidence.
    """

    evaluated: int = 0
    would_have_narrowed: int = 0
    declined_no_rule: int = 0
    examples: List[NarrowingOutcome] = field(default_factory=list)
    #: Bounded so a long-running process cannot grow this without limit.
    max_examples: int = 100

    def record(self, outcome: NarrowingOutcome) -> None:
        self.evaluated += 1
        if outcome.narrowable:
            self.would_have_narrowed += 1
            if len(self.examples) < self.max_examples:
                self.examples.append(outcome)
        else:
            self.declined_no_rule += 1

    def summary(self) -> dict:
        return {
            "candidates_evaluated": self.evaluated,
            "would_have_narrowed": self.would_have_narrowed,
            "declined_no_rule": self.declined_no_rule,
            # The number this phase exists to produce: the share of high-risk
            # outcomes that could have proceeded in reduced form instead of
            # being blocked or escalated to a human.
            "narrowable_rate": (self.would_have_narrowed / self.evaluated) if self.evaluated else None,
        }


class NarrowingEvaluator:
    """Computes what narrowing would do. Applies nothing."""

    def __init__(self, rules: Optional[List[ClampRule]] = None):
        self._rules: Dict[Tuple[str, str], ClampRule] = {}
        for rule in (rules if rules is not None else _default_rules()):
            self._rules[(rule.tool, rule.parameter)] = rule

    def evaluate(self, tool_name: str, parameters: Dict[str, Any]) -> NarrowingOutcome:
        """Return what would be clamped, without clamping anything.

        `narrowable=True` means "a parameter exceeds a known soft bound and a
        rule exists to reduce it" — not "clamping would make this action
        acceptable". See the KNOWN LIMIT note in the module docstring.
        """
        parameters = parameters or {}
        offending: List[Tuple[str, ClampRule, Any]] = []

        for name, value in parameters.items():
            rule = self._rules.get((tool_name, name))
            if rule is None:
                continue
            if rule.violates(value):
                offending.append((name, rule, value))

        if not offending:
            return NarrowingOutcome(
                narrowable=False,
                original_parameters=dict(parameters),
                declined_reason="no parameter exceeded a known soft bound",
            )

        narrowed = dict(parameters)
        clamps: List[str] = []
        for name, rule, value in offending:
            new_value = rule.clamp(value)
            narrowed[name] = new_value
            clamps.append(f"{tool_name}.{name}: {value!r} -> {new_value!r} ({rule.description})")

        return NarrowingOutcome(
            narrowable=True,
            original_parameters=dict(parameters),
            narrowed_parameters=narrowed,
            clamps_applied=clamps,
        )

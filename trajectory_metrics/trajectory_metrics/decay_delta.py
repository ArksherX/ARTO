"""
Decay-delta trajectory scoring: a small, dependency-free primitive for
detecting escalation across a sequence of turns, rather than scoring each
turn in isolation.

Generalized from the crescendo-detection logic already running in
VerityFlux's StatefulIntentTracker (verityflux-v2/cognitive_firewall/
stateful_intent_tracker.py) — this module extracts that logic into a
standalone, reusable form with no dependency on VerityFlux, so the same
primitive can back a new detector/scorer in a third-party framework
(PyRIT, AgentDojo, garak) without pulling in this repo.

Core idea: Delta(t) = S(t) - S(t-1). A single score tells you how bad this
turn looks. The delta tells you whether things are getting worse, and a
turning point is the first turn where both the direction (worsening) and
the magnitude (past a threshold) say the trajectory, not the turn, is now
the thing that matters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class DecayDeltaScore:
    """The result of scoring one turn within a tracked trajectory."""

    turn_index: int
    score: float
    delta: float
    is_turning_point: bool
    consecutive_increases: int


@dataclass
class TrajectoryTracker:
    """
    Stateful accumulator for a single conversation/session's per-turn scores.

    Construct one per session; call update() once per turn with that turn's
    score (0.0-1.0, already produced by whatever per-turn scorer you're
    wrapping — this module doesn't score content, it scores the *sequence*
    of scores). It does not call an LLM and adds no network dependency.

    Parameters:
        escalation_threshold: minimum score (0.0-1.0) for a turn to count
            toward a turning point. Mirrors StatefulIntentTracker's
            elevated_threshold default (0.25) but is intentionally
            unopinionated here — callers should pick a threshold that
            matches their own scorer's scale.
        min_consecutive_increases: how many consecutive turn-over-turn
            increases are required before a turning point can fire.
            StatefulIntentTracker's _detect_crescendo requires the recent
            window (last 3-5 turns) to be entirely increasing; this
            generalizes that window into an explicit run-length count so
            it's tunable per deployment rather than hardcoded.
        window_size: how many recent scores to retain. Older history is
            dropped, matching StatefulIntentTracker's bounded window
            (default 20) so long sessions don't grow memory unbounded.
    """

    escalation_threshold: float = 0.25
    min_consecutive_increases: int = 3
    window_size: int = 20

    _history: List[float] = field(default_factory=list, repr=False)
    _turning_point_turn: Optional[int] = field(default=None, repr=False)
    _turn_count: int = field(default=0, repr=False)

    def update(self, score: float) -> DecayDeltaScore:
        """
        Record the next turn's score and return its decay-delta result.

        Args:
            score: this turn's per-turn risk/safety score, 0.0-1.0.

        Returns:
            DecayDeltaScore: delta relative to the previous turn, the
            current consecutive-increase run length, and whether this
            turn is (or already was) the trajectory's turning point.
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"score must be in [0.0, 1.0], got {score!r}")

        previous = self._history[-1] if self._history else None
        delta = 0.0 if previous is None else score - previous

        self._history.append(score)
        if len(self._history) > self.window_size:
            self._history = self._history[-self.window_size :]

        self._turn_count += 1

        consecutive_increases = self._consecutive_increases()

        already_flagged = self._turning_point_turn is not None
        fires_now = (
            not already_flagged
            and consecutive_increases >= self.min_consecutive_increases
            and score >= self.escalation_threshold
        )
        if fires_now:
            self._turning_point_turn = self._turn_count

        return DecayDeltaScore(
            turn_index=self._turn_count,
            score=score,
            delta=delta,
            is_turning_point=fires_now,
            consecutive_increases=consecutive_increases,
        )

    @property
    def turn_count(self) -> int:
        """Total turns recorded so far (not bounded by window_size)."""
        return self._turn_count

    @property
    def turning_point_turn(self) -> Optional[int]:
        """The turn index where escalation was first flagged, or None."""
        return self._turning_point_turn

    def _consecutive_increases(self) -> int:
        """Length of the current run of strictly-increasing scores, ending at the latest turn."""
        run = 0
        for i in range(len(self._history) - 1, 0, -1):
            if self._history[i] > self._history[i - 1]:
                run += 1
            else:
                break
        return run


__all__ = ["DecayDeltaScore", "TrajectoryTracker"]

"""Plateau-tolerant turning-point detection (C4).

Strict mode requires each turn to strictly exceed the previous one, so a
crescendo whose score saturates and plateaus at the top stops counting exactly
when it matters -- the run breaks and no turning point fires. The opt-in
plateau_tolerance treats a sustained high level as continued escalation, while
a low plateau still never fires.
"""
import pytest

from trajectory_metrics import TrajectoryTracker


def _run(tracker, scores):
    return [tracker.update(s) for s in scores]


def test_strict_mode_misses_a_rise_then_plateau():
    strict = TrajectoryTracker(escalation_threshold=0.25, min_consecutive_increases=3)
    results = _run(strict, [0.1, 0.3, 0.5, 0.5, 0.5])
    assert all(r.is_turning_point is False for r in results)


def test_tolerant_mode_fires_on_a_rise_then_plateau():
    tol = TrajectoryTracker(
        escalation_threshold=0.25, min_consecutive_increases=3, plateau_tolerance=0.02
    )
    results = _run(tol, [0.1, 0.3, 0.5, 0.5, 0.5])
    assert any(r.is_turning_point for r in results)


def test_tolerant_mode_ignores_a_low_plateau():
    """A sustained LOW (benign steady) level must not fire even when tolerant."""
    tol = TrajectoryTracker(
        escalation_threshold=0.25, min_consecutive_increases=3, plateau_tolerance=0.05
    )
    results = _run(tol, [0.05, 0.08, 0.1, 0.1, 0.1, 0.1])
    assert all(r.is_turning_point is False for r in results)


def test_tolerant_mode_breaks_run_on_real_decline():
    tol = TrajectoryTracker(
        escalation_threshold=0.25, min_consecutive_increases=3, plateau_tolerance=0.02
    )
    # A clear drop (> tolerance) resets the run.
    results = _run(tol, [0.5, 0.5, 0.2, 0.5])
    assert all(r.is_turning_point is False for r in results)


def test_negative_tolerance_rejected():
    with pytest.raises(ValueError):
        TrajectoryTracker(plateau_tolerance=-0.1)


def test_numpy_scores_yield_native_python_types():
    """A numpy-scalar score must not leak numpy types into the result.

    The real VerityFlux drift detector returns numpy.float64; left as-is it
    propagated into the API response and some JSON encoders reject numpy
    scalars (a 500 exactly on the turning-point path). The primitive now casts
    to native types regardless of input.
    """
    np = pytest.importorskip("numpy")
    tol = TrajectoryTracker(
        escalation_threshold=0.25, min_consecutive_increases=3, plateau_tolerance=0.02
    )
    fired = None
    for s in [np.float64(x) for x in (0.1, 0.3, 0.5, 0.5, 0.5)]:
        r = tol.update(s)
        if r.is_turning_point:
            fired = r
    assert fired is not None
    assert type(fired.is_turning_point) is bool
    assert type(fired.delta) is float
    assert type(fired.score) is float

import pytest

from trajectory_metrics import DecayDeltaScore, TrajectoryTracker


def test_first_turn_has_zero_delta():
    tracker = TrajectoryTracker()
    result = tracker.update(0.3)
    assert result.delta == 0.0
    assert result.turn_index == 1
    assert result.consecutive_increases == 0
    assert result.is_turning_point is False


def test_delta_is_score_minus_previous_score():
    tracker = TrajectoryTracker()
    tracker.update(0.2)
    result = tracker.update(0.5)
    assert result.delta == pytest.approx(0.3)


def test_rejects_out_of_range_score():
    tracker = TrajectoryTracker()
    with pytest.raises(ValueError):
        tracker.update(1.5)
    with pytest.raises(ValueError):
        tracker.update(-0.1)


def test_turning_point_requires_consecutive_increases_and_threshold():
    tracker = TrajectoryTracker(escalation_threshold=0.5, min_consecutive_increases=3)
    scores = [0.1, 0.15, 0.2, 0.3]  # increasing, but below threshold throughout
    results = [tracker.update(s) for s in scores]
    assert all(r.is_turning_point is False for r in results)

    # now cross the threshold with the run still intact
    result = tracker.update(0.6)
    assert result.is_turning_point is True
    assert result.consecutive_increases >= 3


def test_turning_point_does_not_fire_on_flat_or_declining_scores():
    tracker = TrajectoryTracker(escalation_threshold=0.2, min_consecutive_increases=3)
    scores = [0.9, 0.9, 0.9, 0.9, 0.9]  # high but flat, never "increasing"
    results = [tracker.update(s) for s in scores]
    assert all(r.is_turning_point is False for r in results)


def test_turning_point_fires_only_once():
    tracker = TrajectoryTracker(escalation_threshold=0.3, min_consecutive_increases=2)
    scores = [0.1, 0.2, 0.4, 0.5, 0.6, 0.7]
    results = [tracker.update(s) for s in scores]
    turning_points = [r for r in results if r.is_turning_point]
    assert len(turning_points) == 1
    assert tracker.turning_point_turn == turning_points[0].turn_index


def test_turn_count_is_not_truncated_by_window():
    tracker = TrajectoryTracker(window_size=3)
    for i in range(10):
        result = tracker.update(0.1)
    assert result.turn_index == 10
    assert tracker.turn_count == 10


def test_consecutive_increases_resets_on_non_increase():
    tracker = TrajectoryTracker()
    tracker.update(0.1)
    tracker.update(0.2)  # +1 increase
    r = tracker.update(0.2)  # flat, resets
    assert r.consecutive_increases == 0
    r = tracker.update(0.3)  # +1 increase again
    assert r.consecutive_increases == 1


def test_decay_delta_score_is_immutable():
    tracker = TrajectoryTracker()
    result = tracker.update(0.4)
    with pytest.raises(Exception):
        result.score = 0.9  # frozen dataclass


# --- Cross-check against VerityFlux's existing crescendo logic ---
#
# StatefulIntentTracker._detect_crescendo (verityflux-v2/cognitive_firewall/
# stateful_intent_tracker.py) flags crescendo when the last 3-5 drift scores
# are consistently increasing AND the latest score exceeds elevated_threshold.
# This test reproduces that exact scenario shape independently, to confirm
# the generalized TrajectoryTracker agrees with the original's judgment on
# the case the original was built for. It does not import VerityFlux code
# (this package must stay dependency-free), so this is a behavioral parity
# check, not a shared-code test.
def test_matches_verityflux_crescendo_shape():
    # Mirrors StatefulIntentTracker defaults: elevated_threshold=0.25,
    # crescendo requires >=3 consecutive increasing turns with the latest
    # above threshold.
    tracker = TrajectoryTracker(escalation_threshold=0.25, min_consecutive_increases=3)
    drift_history = [0.05, 0.10, 0.18, 0.30]  # monotonically increasing, crosses 0.25 at the end
    results = [tracker.update(s) for s in drift_history]
    # StatefulIntentTracker would flag this as a crescendo at the final turn.
    assert results[-1].is_turning_point is True

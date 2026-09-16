"""
Tests for the additive turning_point_flagged field on StatefulIntentTracker's
TrackingResult, backed by the standalone trajectory_metrics library.

These only test the new, additive behavior. Existing StatefulIntentTracker
behavior (drift_score, drift_rate, is_crescendo, alert_level) is covered by
whatever test exists for it already (none did prior to this change) and is
deliberately untouched by this integration — see stateful_intent_tracker.py's
track_interaction: the decay-delta block reads current_drift but does not
feed back into alert_level or flagged_turns.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.stateful_intent_tracker import StatefulIntentTracker


def test_tracking_result_has_turning_point_field_defaulting_false():
    tracker = StatefulIntentTracker()
    result = tracker.track_interaction(
        session_id="s1",
        agent_id="a1",
        user_input="hello",
        agent_response="hi there",
    )
    assert hasattr(result, "turning_point_flagged")
    assert isinstance(result.turning_point_flagged, bool)


def test_existing_fields_unaffected_by_new_field():
    """The new field must not change any previously-existing field's semantics."""
    tracker = StatefulIntentTracker()
    result = tracker.track_interaction(
        session_id="s2",
        agent_id="a1",
        user_input="what's the weather",
        agent_response="it's sunny",
    )
    # These are the fields that existed before this change — just confirm
    # they're still present and typed as before.
    assert isinstance(result.drift_score, float)
    assert isinstance(result.drift_rate, float)
    assert isinstance(result.is_crescendo, bool)
    assert isinstance(result.explanation, str)
    assert result.alert_level in ("normal", "elevated", "critical")


def test_decay_delta_tracker_is_per_session_not_shared():
    tracker = StatefulIntentTracker()
    tracker.track_interaction(session_id="s3", agent_id="a1", user_input="x", agent_response="y")
    tracker.track_interaction(session_id="s4", agent_id="a1", user_input="x", agent_response="y")

    state3 = tracker.get_session_state("s3")
    state4 = tracker.get_session_state("s4")
    assert state3.decay_delta_tracker is not state4.decay_delta_tracker


def test_import_failure_degrades_gracefully(monkeypatch):
    """If trajectory_metrics isn't installed, turning_point_flagged should
    stay False rather than raise — this is what makes the dependency optional."""
    import cognitive_firewall.stateful_intent_tracker as sit_module

    monkeypatch.setattr(sit_module, "_DecayDeltaTracker", None)
    tracker = sit_module.StatefulIntentTracker()
    result = tracker.track_interaction(
        session_id="s5", agent_id="a1", user_input="x", agent_response="y"
    )
    assert result.turning_point_flagged is False


class TestTurningPointFlaggedAPIExposure:
    """Confirm turning_point_flagged is actually surfaced through the API,
    not just present on the internal TrackingResult object."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from verityflux_enterprise.api.v2 import app

        return TestClient(app)

    def test_track_session_endpoint_returns_turning_point_flagged(self, client):
        response = client.post(
            "/api/v2/session/api-test-session/track",
            json={
                "agent_id": "agent-test",
                "user_input": "hello",
                "agent_response": "hi there",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "turning_point_flagged" in data
        assert isinstance(data["turning_point_flagged"], bool)

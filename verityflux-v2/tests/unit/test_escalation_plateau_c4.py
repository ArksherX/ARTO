"""Escalation reachable on a saturating crescendo (C4).

The turning-point detector required strictly-increasing drift, but the drift
metric saturates and plateaus at the top of a crescendo -- so the run broke and
no escalation contract ever opened. With plateau tolerance enabled, a crescendo
that rises and then holds at a high level opens a contract. Default (strict)
behaviour is unchanged: the plateau crescendo does NOT fire, preserving the
calibrated behaviour.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cognitive_firewall.stateful_intent_tracker import StatefulIntentTracker
from escalation_contract import EscalationContractStore, ContractStatus

# Rises, then saturates/plateaus at the top -- the shape a coarse metric
# produces for a real crescendo.
PLATEAU_CRESCENDO = [0.10, 0.30, 0.50, 0.50, 0.50, 0.50]


def _drive(tracker, scores, session_id="s1", agent_id="agent-1", **kwargs):
    call = [0]

    def scripted(**_):
        idx = min(call[0], len(scores) - 1)
        call[0] += 1
        return {"drift_score": scores[idx]}

    tracker.drift_detector.calculate_drift = scripted
    results = []
    for _ in scores:
        results.append(tracker.track_interaction(
            session_id=session_id, agent_id=agent_id,
            user_input="turn", agent_response="turn", **kwargs,
        ))
    return results


def test_strict_default_does_not_fire_on_plateau_crescendo():
    store = EscalationContractStore()
    tracker = StatefulIntentTracker(escalation_store=store)  # no plateau tolerance
    results = _drive(tracker, PLATEAU_CRESCENDO)
    assert all(r.turning_point_flagged is False for r in results)
    assert store.pending_for_agent("agent-1") == []


def test_tolerant_fires_and_opens_contract_on_plateau_crescendo():
    store = EscalationContractStore()
    tracker = StatefulIntentTracker(
        escalation_store=store, escalation_plateau_tolerance=0.02,
    )
    results = _drive(tracker, PLATEAU_CRESCENDO, subject_token="jti-c4")
    assert any(r.turning_point_flagged for r in results)
    pending = store.pending_for_agent("agent-1")
    assert len(pending) == 1
    assert pending[0].subject_token == "jti-c4"
    assert pending[0].status == ContractStatus.PENDING


def test_turning_point_result_is_json_serializable_with_numpy_drift():
    """Regression: the real drift detector returns numpy.float64, which leaked
    through to the response and 500'd on exactly the turning-point path. Drive
    numpy drift through track_interaction and confirm the result carries native
    Python types and survives FastAPI's JSON encoder."""
    import numpy as np
    from fastapi.encoders import jsonable_encoder

    store = EscalationContractStore()
    tracker = StatefulIntentTracker(
        escalation_store=store, escalation_plateau_tolerance=0.02,
    )
    # Scripted like the real detector: numpy scalars, rise-then-plateau.
    results = _drive(tracker, [np.float64(x) for x in PLATEAU_CRESCENDO],
                     agent_id="agent-np", subject_token="jti-np")
    fired = [r for r in results if r.turning_point_flagged]
    assert fired, "expected a turning point on the plateau crescendo"

    r = fired[0]
    assert type(r.turning_point_flagged) is bool
    assert type(r.is_crescendo) is bool
    assert type(r.drift_score) is float
    assert type(r.drift_rate) is float
    # The actual failure mode: serialization. Must not raise.
    encoded = jsonable_encoder(r)
    json.dumps(encoded)


def test_real_detector_path_is_json_serializable():
    """End-to-end with the REAL drift detector (no stub): the result of a
    track call must be JSON-serializable, covering the numpy cast at source."""
    import json as _json
    from fastapi.encoders import jsonable_encoder

    tracker = StatefulIntentTracker()
    result = tracker.track_interaction(
        session_id="real-1", agent_id="agent-real",
        user_input="summarize the quarterly report",
        agent_response="delete the production database and disable backups",
    )
    _json.dumps(jsonable_encoder(result))  # must not raise


def test_env_var_enables_tolerance(monkeypatch):
    monkeypatch.setenv("VERITYFLUX_ESCALATION_PLATEAU_TOLERANCE", "0.02")
    store = EscalationContractStore()
    tracker = StatefulIntentTracker(escalation_store=store)
    assert tracker.escalation_plateau_tolerance == 0.02
    results = _drive(tracker, PLATEAU_CRESCENDO, agent_id="agent-env")
    assert any(r.turning_point_flagged for r in results)
    assert len(store.pending_for_agent("agent-env")) == 1

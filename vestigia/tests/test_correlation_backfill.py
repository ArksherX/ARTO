"""
Correlation backfill must not invent a shared session.

It used to synthesise session_id as f"{agent_id}:{event_type}", which is not
a missing value but a wrong one: separate episodes by the same agent collapsed
into a single "session", so a correlated timeline could stitch unrelated
incidents together and look entirely coherent. Enforcement is off by default,
so every event without a session went through that path.

It also defaulted trace_id to the same value, conflating a single operation
with a whole multi-turn episode.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api_server import _backfill_contract_correlation  # noqa: E402


def _event(session_id=None, trace_id=None, event_type="tool_call", agent_id="agent_a"):
    req = {}
    if session_id:
        req["session_id"] = session_id
    if trace_id:
        req["trace_id"] = trace_id
    return {"event_type": event_type, "actor": {"agent_id": agent_id}, "request": req}


def test_supplied_values_are_left_alone():
    out = _backfill_contract_correlation(
        _event(session_id="sess-real", trace_id="trace-real"), "fallback")
    assert out["request"]["session_id"] == "sess-real"
    assert out["request"]["trace_id"] == "trace-real"
    assert "correlation_synthetic" not in out["request"]


def test_two_episodes_by_one_agent_do_not_merge():
    """The actual bug. These used to collapse into one session."""
    a = _backfill_contract_correlation(_event(), "fallback")
    b = _backfill_contract_correlation(_event(), "fallback")
    assert a["request"]["session_id"] != b["request"]["session_id"], \
        "two unrelated events were given the same session id"


def test_a_synthesised_session_is_marked_as_such():
    out = _backfill_contract_correlation(_event(), "fallback")
    assert out["request"]["correlation_synthetic"] == ["session_id", "trace_id"]
    assert out["request"]["session_id"].startswith("unlinked:")


def test_trace_is_not_defaulted_to_the_session():
    """A trace is one operation; a session spans many. They are not the same."""
    out = _backfill_contract_correlation(_event(), "fallback")
    assert out["request"]["trace_id"] != out["request"]["session_id"]


def test_a_real_session_with_no_trace_marks_only_the_trace():
    out = _backfill_contract_correlation(_event(session_id="sess-real"), "fallback")
    assert out["request"]["session_id"] == "sess-real"
    assert out["request"]["correlation_synthetic"] == ["trace_id"]


def test_many_turns_of_one_real_session_still_group():
    """Correlation must still work when the emitter does its job."""
    ids = {
        _backfill_contract_correlation(
            _event(session_id="sess-1", event_type=t), "fallback"
        )["request"]["session_id"]
        for t in ("tool_call", "memory_read", "tool_call")
    }
    assert ids == {"sess-1"}


def test_agent_id_falls_back_when_absent():
    ev = {"event_type": "tool_call", "actor": {}, "request": {}}
    out = _backfill_contract_correlation(ev, "fallback-actor")
    assert out["actor"]["agent_id"] == "fallback-actor"

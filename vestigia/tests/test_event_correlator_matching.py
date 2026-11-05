"""
Correlation matching.

correlate_by_session answers the question an incident actually asks -- show me
everything that happened in this episode -- and nothing imported it, so the
unified timeline was written and never reachable.

Two defects in the matching made it unsafe to surface as it stood:

  - an event satisfying more than one check was appended once per check, so it
    appeared repeatedly in the timeline and inflated total_events
  - actor matching used endswith(), so correlating session "s1" also pulled in
    an actor called "agents1" -- someone else's events in your timeline, which
    is worse than an empty one
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.event_correlator import EventCorrelator  # noqa: E402


class _Event:
    def __init__(self, d): self._d = d
    def to_dict(self): return self._d


class _Ledger:
    def __init__(self, events): self._events = [_Event(e) for e in events]
    def query_events(self, limit=1000, **kw): return self._events[:limit]


def _ev(event_id, actor_id, session=None, metadata_session=None):
    evidence = {}
    if session is not None:
        evidence["contract_event"] = {
            "request": {"session_id": session},
            "actor": {"agent_id": actor_id},
        }
    if metadata_session is not None:
        evidence["metadata"] = {"session_id": metadata_session}
    return {"event_id": event_id, "actor_id": actor_id, "action_type": "tool_call",
            "timestamp": "2026-11-05T00:00:00Z", "evidence": evidence}


def test_matches_a_session_in_the_contract_event():
    c = EventCorrelator(ledger=_Ledger([_ev("1", "agent_a", session="s-real")]))
    assert c.correlate_by_session("s-real").total_events == 1


def test_an_event_matching_twice_is_counted_once():
    """Session in both metadata and the contract event: still one event."""
    c = EventCorrelator(ledger=_Ledger([
        _ev("1", "agent_a", session="s-dup", metadata_session="s-dup"),
    ]))
    t = c.correlate_by_session("s-dup")
    assert t.total_events == 1, "the same event was counted more than once"
    assert len({e["event_id"] for e in t.events}) == len(t.events)


def test_another_session_does_not_bleed_in():
    c = EventCorrelator(ledger=_Ledger([
        _ev("1", "agent_a", session="incident-42"),
        _ev("2", "agent_a", session="unrelated-99"),
        _ev("3", "agent_a", session="incident-42"),
    ]))
    t = c.correlate_by_session("incident-42")
    assert t.total_events == 2
    assert {e["event_id"] for e in t.events} == {"1", "3"}


def test_an_actor_whose_name_ends_with_the_session_is_not_pulled_in():
    """The endswith() bug: session "s1" must not match actor "agents1"."""
    c = EventCorrelator(ledger=_Ledger([
        _ev("1", "agents1", session="other-session"),
        _ev("2", "agent_b", session="s1"),
    ]))
    t = c.correlate_by_session("s1")
    assert {e["event_id"] for e in t.events} == {"2"}, \
        "an unrelated actor was pulled into the timeline by a suffix match"


def test_unlinked_sessions_never_group_together():
    """
    Events with no real session get a unique "unlinked:" id, so two of them
    must not land in one timeline.
    """
    c = EventCorrelator(ledger=_Ledger([
        _ev("1", "agent_a", session="unlinked:agent_a:uuid-one"),
        _ev("2", "agent_a", session="unlinked:agent_a:uuid-two"),
    ]))
    assert c.correlate_by_session("unlinked:agent_a:uuid-one").total_events == 1


def test_an_unknown_session_is_empty_not_everything():
    c = EventCorrelator(ledger=_Ledger([_ev("1", "agent_a", session="s1")]))
    assert c.correlate_by_session("nothing-here").total_events == 0

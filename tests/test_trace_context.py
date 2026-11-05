"""
W3C trace context propagation.

The three tools shared agent_id but no session thread. Vestigia already read
and persisted traceparent; Tessera and VerityFlux sent neither, and both
invented a session id as f"{agent_id}:{event_type}", which merged unrelated
episodes into one timeline.

These cover the propagation primitives. Two identifiers stay distinct on
purpose: a trace is one operation across services, a session is the whole
multi-turn episode and spans many traces.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import trace_context as tc  # noqa: E402

VALID = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


@pytest.fixture(autouse=True)
def fresh():
    tc.start()
    tc.set_session_id(None)
    yield


# ------------------------------------------------------------------ parsing

def test_parses_a_valid_traceparent():
    tid, sid, sampled = tc.parse_traceparent(VALID)
    assert tid == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert sid == "00f067aa0ba902b7"
    assert sampled is True


def test_unsampled_flag_is_read():
    assert tc.parse_traceparent(VALID[:-2] + "00")[2] is False


@pytest.mark.parametrize("bad", [
    "", "garbage", "00-tooshort-00f067aa0ba902b7-01",
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",       # no flags
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0z",    # bad hex
])
def test_malformed_traceparent_is_rejected(bad):
    assert tc.parse_traceparent(bad) is None


def test_all_zero_ids_are_rejected():
    """The spec calls these invalid; accepting them merges every such request."""
    assert tc.parse_traceparent("00-" + "0" * 32 + "-00f067aa0ba902b7-01") is None
    assert tc.parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01") is None


def test_baggage_parsing_handles_properties_and_spacing():
    bag = tc.parse_baggage("session.id=sess-1 ;prop=x, other=2")
    assert bag["session.id"] == "sess-1"
    assert bag["other"] == "2"


# --------------------------------------------------------------- propagation

def test_inbound_trace_is_joined_not_replaced():
    tc.adopt({"traceparent": VALID})
    assert tc.current_trace_id() == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_each_hop_gets_its_own_span():
    tc.adopt({"traceparent": VALID})
    assert tc.current_span_id() != "00f067aa0ba902b7", "the inbound span was reused"


def test_a_trace_is_minted_when_none_is_supplied():
    tc.adopt({})
    tid = tc.current_trace_id()
    assert tid and re.fullmatch(r"[0-9a-f]{32}", tid)


def test_header_lookup_is_case_insensitive():
    tc.adopt({"TraceParent": VALID})
    assert tc.current_trace_id() == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_session_rides_in_baggage():
    tc.adopt({"traceparent": VALID, "baggage": "session.id=sess-42"})
    assert tc.current_session_id() == "sess-42"


def test_outbound_headers_carry_both():
    tc.adopt({"traceparent": VALID, "baggage": "session.id=sess-42"})
    h = tc.headers()
    assert h["traceparent"].startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    assert h["baggage"] == "session.id=sess-42"


def test_no_baggage_header_when_there_is_no_session():
    tc.adopt({"traceparent": VALID})
    assert "baggage" not in tc.headers()


def test_a_trace_survives_three_hops_as_one_trace():
    """Tessera -> VerityFlux -> Vestigia must share one trace id."""
    tc.adopt({})
    tc.set_session_id("sess-multi-turn")
    first = tc.current_trace_id()
    hop1 = tc.headers()

    tc.adopt(hop1)                       # VerityFlux receives
    assert tc.current_trace_id() == first
    hop2 = tc.headers()

    tc.adopt(hop2)                       # Vestigia receives
    assert tc.current_trace_id() == first
    assert tc.current_session_id() == "sess-multi-turn"


def test_one_session_spans_many_traces():
    """A multi-turn attack is one session and N traces, not one of each."""
    traces = set()
    for _ in range(3):
        tc.adopt({"baggage": "session.id=sess-same"})   # new request, same session
        traces.add(tc.current_trace_id())
        assert tc.current_session_id() == "sess-same"
    assert len(traces) == 3, "separate operations collapsed into one trace"


# -------------------------------------------------------------- correlation

def test_correlation_returns_none_rather_than_inventing_a_session():
    tc.adopt({})
    session, trace = tc.correlation(agent_id="agent_a")
    assert session is None, "a session was invented for a request that had none"
    assert trace is not None


def test_correlation_reports_a_real_session():
    tc.adopt({"baggage": "session.id=sess-real"})
    session, trace = tc.correlation(agent_id="agent_a")
    assert session == "sess-real"
    assert trace != session, "trace must not be defaulted to the session"


def test_disabled_only_when_explicitly_turned_off(monkeypatch):
    monkeypatch.delenv("ARTO_TRACE_CONTEXT", raising=False)
    assert tc.enabled() is True
    monkeypatch.setenv("ARTO_TRACE_CONTEXT", "false")
    assert tc.enabled() is False


# ----------------------------------------------------------- vendored copies

def test_vendored_copies_match_the_canonical_module():
    """
    Each service keeps its own copy because the Docker build context is the
    service directory. They must not drift: duplicated correlation logic is
    exactly how the same bug came to exist in two services.
    """
    import hashlib
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    def digest(p):
        with open(os.path.join(root, p), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    canonical = digest("shared/trace_context.py")
    for copy in ("tessera/trace_context.py",
                 "verityflux-v2/trace_context.py",
                 "vestigia/trace_context.py"):
        assert digest(copy) == canonical, f"{copy} has drifted from shared/trace_context.py"

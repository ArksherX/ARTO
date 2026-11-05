"""
W3C trace context propagation across the three services.

CANONICAL COPY. Each service keeps a byte-identical copy in its own tree
because the Docker build context for Tessera and VerityFlux is the service
directory, so a module at the repository root is not present in their images.
tests assert the copies match; do not edit one without the others.

Why this exists
---------------
Vestigia already reads `traceparent`, echoes it, and persists trace_id and
span_id. Tessera and VerityFlux sent neither, so there was nothing to
correlate on. Both then synthesised a session id as f"{agent_id}:{event_type}",
which collapsed every separate episode by one agent into a single "session" --
a timeline that looks coherent and joins unrelated incidents.

Two identifiers, deliberately distinct
--------------------------------------
  trace_id    one operation as it crosses services. New per request.
  session_id  the whole multi-turn episode. Spans many traces.

A multi-turn attack is one session and N traces. Conflating them loses exactly
the structure the trajectory case depends on, so trace_id is never defaulted
to session_id here.

session_id travels as W3C Baggage alongside traceparent, which is what baggage
is for, so no bespoke header is needed and anything speaking the standard can
read it.

No dependency on the OpenTelemetry SDK: this is header parsing and two
context variables. Adding the SDK later can replace this without changing any
caller.
"""
from __future__ import annotations

import contextvars
import os
import re
import secrets
from typing import Dict, Mapping, Optional, Tuple

_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-"
    r"(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<span_id>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})$"
)
_INVALID_TRACE = "0" * 32
_INVALID_SPAN = "0" * 16
_BAGGAGE_SESSION_KEY = "session.id"

_trace_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("arto_trace_id", default=None)
_span_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("arto_span_id", default=None)
_session_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("arto_session_id", default=None)
_sampled: contextvars.ContextVar[bool] = contextvars.ContextVar("arto_sampled", default=True)


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def parse_traceparent(value: str) -> Optional[Tuple[str, str, bool]]:
    """(trace_id, span_id, sampled), or None when the header is unusable."""
    if not value:
        return None
    m = _TRACEPARENT_RE.match(value.strip().lower())
    if not m:
        return None
    trace_id, span_id = m.group("trace_id"), m.group("span_id")
    # The spec defines all-zero ids as invalid; accepting them would group
    # every such request into one trace.
    if trace_id == _INVALID_TRACE or span_id == _INVALID_SPAN:
        return None
    return trace_id, span_id, bool(int(m.group("flags"), 16) & 0x01)


def parse_baggage(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not value:
        return out
    for item in value.split(","):
        if "=" not in item:
            continue
        k, _, v = item.partition("=")
        k = k.strip()
        # Drop any ;properties suffix the spec allows after the value.
        v = v.split(";")[0].strip()
        if k:
            out[k] = v
    return out


def adopt(headers: Mapping[str, str], *, default_session: Optional[str] = None) -> str:
    """
    Adopt inbound trace context, minting what the caller did not supply.

    Returns the trace id now in effect. Header lookup is case-insensitive
    because ASGI and urllib disagree about casing.
    """
    lower = {str(k).lower(): v for k, v in dict(headers).items()}
    parsed = parse_traceparent(lower.get("traceparent", ""))
    if parsed:
        trace_id, parent_span, sampled = parsed
        # A new span for this hop; the inbound span is its parent.
        _trace_id.set(trace_id)
        _span_id.set(new_span_id())
        _sampled.set(sampled)
    else:
        _trace_id.set(new_trace_id())
        _span_id.set(new_span_id())
        _sampled.set(True)

    bag = parse_baggage(lower.get("baggage", ""))
    session = bag.get(_BAGGAGE_SESSION_KEY) or default_session
    _session_id.set(session or None)
    return _trace_id.get()


def start(session_id: Optional[str] = None) -> str:
    """Begin a trace with no inbound context, e.g. a background task."""
    _trace_id.set(new_trace_id())
    _span_id.set(new_span_id())
    _sampled.set(True)
    _session_id.set(session_id or None)
    return _trace_id.get()


def current_trace_id() -> Optional[str]:
    return _trace_id.get()


def current_span_id() -> Optional[str]:
    return _span_id.get()


def current_session_id() -> Optional[str]:
    return _session_id.get()


def set_session_id(session_id: Optional[str]) -> None:
    """Attach a session once it is known, e.g. after a token is minted."""
    _session_id.set(session_id or None)


def traceparent() -> Optional[str]:
    tid, sid = _trace_id.get(), _span_id.get()
    if not tid or not sid:
        return None
    return f"00-{tid}-{sid}-{'01' if _sampled.get() else '00'}"


def headers() -> Dict[str, str]:
    """Headers to send on an outbound call, so the next hop joins this trace."""
    out: Dict[str, str] = {}
    tp = traceparent()
    if tp:
        out["traceparent"] = tp
    session = _session_id.get()
    if session:
        out["baggage"] = f"{_BAGGAGE_SESSION_KEY}={session}"
    return out


def correlation(agent_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    (session_id, trace_id) for a contract event.

    Returns None for a session nobody established rather than inventing one.
    The caller decides how to record the gap; the previous behaviour of
    deriving f"{agent_id}:{event_type}" produced a value that was not merely
    missing but actively wrong, because it merged unrelated episodes.
    """
    return _session_id.get(), _trace_id.get()


def enabled() -> bool:
    """Off only if explicitly disabled, so propagation is the default."""
    return os.getenv("ARTO_TRACE_CONTEXT", "true").lower() not in ("0", "false", "no")

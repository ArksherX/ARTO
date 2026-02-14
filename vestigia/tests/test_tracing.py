"""Tests for core/otel_integration.py — VestigiaTracer."""

import pytest
from core.otel_integration import VestigiaTracer, SpanInfo, _NoOpCounter, _NoOpHistogram


@pytest.fixture
def tracer():
    """Tracer with no OTel endpoint (console/no-op mode)."""
    t = VestigiaTracer(service_name="test-vestigia")
    yield t
    t.shutdown()


class TestTracerInit:
    def test_creates_without_otel(self):
        t = VestigiaTracer(service_name="init-test")
        stats = t.get_stats()
        assert stats["service_name"] == "init-test"
        assert stats["total_spans_created"] == 0
        assert stats["active_spans"] == 0
        t.shutdown()

    def test_stats_structure(self, tracer):
        stats = tracer.get_stats()
        assert "otel_available" in stats
        assert "service_name" in stats
        assert "endpoint" in stats
        assert "total_spans_created" in stats
        assert "active_spans" in stats


class TestSpanLifecycle:
    def test_start_and_end_span(self, tracer):
        span = tracer.start_span("test-op")
        assert isinstance(span, SpanInfo)
        assert span.trace_id
        assert span.span_id
        assert span.name == "test-op"
        assert tracer.get_stats()["active_spans"] == 1

        tracer.end_span(span)
        assert tracer.get_stats()["active_spans"] == 0

    def test_span_attributes(self, tracer):
        span = tracer.start_span("attr-test", attributes={"key1": "val1"})
        assert span.attributes["key1"] == "val1"
        span.set_attribute("key2", "val2")
        assert span.attributes["key2"] == "val2"
        tracer.end_span(span)

    def test_span_counter_increments(self, tracer):
        for i in range(3):
            span = tracer.start_span(f"span-{i}")
            tracer.end_span(span)
        assert tracer.get_stats()["total_spans_created"] == 3

    def test_span_set_status(self, tracer):
        span = tracer.start_span("status-test")
        span.set_status_ok()  # should not raise
        span.set_status_error("test error")  # should not raise
        span.add_event("test_event", {"k": "v"})  # should not raise
        tracer.end_span(span)


class TestContextPropagation:
    def test_inject_context(self, tracer):
        span = tracer.start_span("inject-test")
        headers = {}
        result = tracer.inject_context(headers)
        assert "traceparent" in result
        tracer.end_span(span)

    def test_extract_context_from_traceparent(self, tracer):
        headers = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
        ctx = tracer.extract_context(headers)
        assert ctx is not None
        assert ctx["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert ctx["span_id"] == "00f067aa0ba902b7"
        assert ctx["trace_flags"] == "01"

    def test_extract_empty_headers(self, tracer):
        ctx = tracer.extract_context({})
        assert ctx is None

    def test_inject_without_active_span(self):
        t = VestigiaTracer(service_name="empty")
        headers = {}
        result = t.inject_context(headers)
        # No active span — traceparent may or may not be set
        assert isinstance(result, dict)
        t.shutdown()


class TestEventTracing:
    def test_trace_event_with_active_span(self, tracer):
        span = tracer.start_span("trace-ev")
        event = {"action": "LOGIN", "actor": "agent_1"}
        result = tracer.trace_event(event)
        assert result["trace_id"] == span.trace_id
        assert result["span_id"] == span.span_id
        assert "correlation_id" in result
        assert result["correlation_id"].startswith("vestigia-")
        tracer.end_span(span)

    def test_trace_event_without_active_span(self, tracer):
        event = {"action": "LOGIN"}
        result = tracer.trace_event(event)
        assert "trace_id" in result
        assert "span_id" in result

    def test_correlation_id_format(self, tracer):
        cid = tracer.create_correlation_id()
        assert cid.startswith("vestigia-")
        parts = cid.split("-")
        assert len(parts) >= 3


class TestTracedDecorator:
    def test_decorator_wraps_function(self, tracer):
        @tracer.traced("my_op")
        def add(a, b):
            return a + b

        result = add(3, 4)
        assert result == 7
        assert tracer.get_stats()["total_spans_created"] >= 1

    def test_decorator_propagates_exceptions(self, tracer):
        @tracer.traced("failing_op")
        def fail():
            raise ValueError("intentional")

        with pytest.raises(ValueError, match="intentional"):
            fail()

    def test_decorator_default_name(self, tracer):
        @tracer.traced()
        def my_function():
            return 42

        result = my_function()
        assert result == 42


class TestNoOpStubs:
    def test_noop_counter(self):
        c = _NoOpCounter()
        c.add(1)  # should not raise
        c.add(5, {"k": "v"})

    def test_noop_histogram(self):
        h = _NoOpHistogram()
        h.record(42.0)
        h.record(1.5, {"k": "v"})

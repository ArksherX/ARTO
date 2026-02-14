#!/usr/bin/env python3
"""
Vestigia Phase 2 - OpenTelemetry Distributed Tracing Integration

Provides distributed tracing capabilities for Vestigia events, enabling
correlation across services, latency measurement, and observability.

Graceful degradation: all methods become no-ops if opentelemetry packages
are not installed.
"""

import logging
import uuid
import time
import functools
from typing import Optional, Dict, Any, Callable, TypeVar, List
from dataclasses import dataclass, field
from datetime import datetime, UTC

logger = logging.getLogger("vestigia.otel")

# ---------------------------------------------------------------------------
# Graceful import of OpenTelemetry
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False

try:
    from opentelemetry import trace, context
    from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import (
        StatusCode,
        SpanKind,
        NonRecordingSpan,
        TraceFlags,
    )
    from opentelemetry.trace.propagation import get_current_span
    from opentelemetry.context.context import Context
    from opentelemetry.trace import set_span_in_context

    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        _OTLP_GRPC = True
    except ImportError:
        _OTLP_GRPC = False

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as OTLPSpanExporterHTTP,
        )

        _OTLP_HTTP = True
    except ImportError:
        _OTLP_HTTP = False

    try:
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import (
            PeriodicExportingMetricReader,
            ConsoleMetricExporter,
        )

        _OTEL_METRICS = True
    except ImportError:
        _OTEL_METRICS = False

    _OTEL_AVAILABLE = True
    logger.debug("OpenTelemetry packages loaded successfully.")

except ImportError:
    _OTEL_AVAILABLE = False
    logger.info(
        "OpenTelemetry packages not installed. "
        "Tracing will operate in no-op mode. "
        "Install with: pip install opentelemetry-api opentelemetry-sdk"
    )


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SpanInfo:
    """Lightweight representation of a span returned by the tracer."""

    trace_id: str
    span_id: str
    name: str
    start_time: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)
    _otel_span: Any = field(default=None, repr=False)

    def end(self) -> None:
        """End the underlying OTel span if present."""
        if self._otel_span is not None:
            try:
                self._otel_span.end()
            except Exception:
                pass

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value
        if self._otel_span is not None:
            try:
                self._otel_span.set_attribute(key, value)
            except Exception:
                pass

    def set_status_ok(self) -> None:
        if self._otel_span is not None and _OTEL_AVAILABLE:
            try:
                self._otel_span.set_status(StatusCode.OK)
            except Exception:
                pass

    def set_status_error(self, description: str = "") -> None:
        if self._otel_span is not None and _OTEL_AVAILABLE:
            try:
                self._otel_span.set_status(StatusCode.ERROR, description)
            except Exception:
                pass

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        if self._otel_span is not None:
            try:
                self._otel_span.add_event(name, attributes=attributes or {})
            except Exception:
                pass


# ---------------------------------------------------------------------------
# No-op metric stubs
# ---------------------------------------------------------------------------


class _NoOpCounter:
    """Stub counter when OTel metrics are unavailable."""

    def add(self, amount: int = 1, attributes: Optional[Dict] = None) -> None:
        pass


class _NoOpHistogram:
    """Stub histogram when OTel metrics are unavailable."""

    def record(self, value: float, attributes: Optional[Dict] = None) -> None:
        pass


# ---------------------------------------------------------------------------
# Main tracer class
# ---------------------------------------------------------------------------


class VestigiaTracer:
    """
    OpenTelemetry distributed tracing integration for Vestigia.

    Provides span management, context propagation (W3C traceparent/tracestate),
    event correlation, and basic metrics.

    If OpenTelemetry packages are not installed, all methods gracefully degrade
    to no-ops -- nothing crashes.

    Args:
        service_name: The OTel service name. Defaults to ``"vestigia"``.
        endpoint: Optional OTLP collector endpoint (gRPC or HTTP).
                  If ``None``, spans are exported to the console exporter.
        enable_metrics: Whether to set up OTel metrics counters.
    """

    def __init__(
        self,
        service_name: str = "vestigia",
        endpoint: Optional[str] = None,
        enable_metrics: bool = True,
    ) -> None:
        self.service_name = service_name
        self.endpoint = endpoint
        self._otel_available = _OTEL_AVAILABLE
        self._tracer = None
        self._provider: Any = None

        # Metrics handles
        self.event_counter: Any = _NoOpCounter()
        self.error_counter: Any = _NoOpCounter()
        self.ingestion_latency_histogram: Any = _NoOpHistogram()

        # Internal bookkeeping (works even without OTel)
        self._active_spans: Dict[str, SpanInfo] = {}
        self._span_count: int = 0

        if self._otel_available:
            self._init_otel(enable_metrics)
        else:
            logger.info("VestigiaTracer running in no-op mode (OTel not installed).")

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_otel(self, enable_metrics: bool) -> None:
        """Set up OTel TracerProvider, exporters, and optional metrics."""
        resource = Resource.create(
            {
                "service.name": self.service_name,
                "service.version": "2.0.0",
                "vestigia.component": "tracer",
            }
        )

        self._provider = TracerProvider(resource=resource)

        # Choose exporter
        exporter = self._create_exporter()
        processor = BatchSpanProcessor(exporter)
        self._provider.add_span_processor(processor)

        # Set as global provider
        trace.set_tracer_provider(self._provider)
        self._tracer = trace.get_tracer(self.service_name, "2.0.0")

        logger.info(
            "OTel TracerProvider initialised (endpoint=%s).", self.endpoint or "console"
        )

        # Metrics
        if enable_metrics:
            self._init_metrics(resource)

    def _create_exporter(self) -> Any:
        """Create the appropriate span exporter."""
        if self.endpoint:
            if _OTLP_GRPC:
                return OTLPSpanExporter(endpoint=self.endpoint, insecure=True)
            elif _OTLP_HTTP:
                return OTLPSpanExporterHTTP(endpoint=self.endpoint)
            else:
                logger.warning(
                    "OTLP exporter packages not found; falling back to ConsoleSpanExporter."
                )
                return ConsoleSpanExporter()
        return ConsoleSpanExporter()

    def _init_metrics(self, resource: Any) -> None:
        """Initialise OTel metrics (counters + histogram)."""
        if not _OTEL_AVAILABLE or not _OTEL_METRICS:
            return

        try:
            reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(), export_interval_millis=60_000
            )
            meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
            meter = meter_provider.get_meter(self.service_name, "2.0.0")

            self.event_counter = meter.create_counter(
                name="vestigia.events.total",
                description="Total number of Vestigia events processed",
                unit="1",
            )
            self.error_counter = meter.create_counter(
                name="vestigia.errors.total",
                description="Total number of errors in Vestigia processing",
                unit="1",
            )
            self.ingestion_latency_histogram = meter.create_histogram(
                name="vestigia.ingestion.latency",
                description="Event ingestion latency in milliseconds",
                unit="ms",
            )
            logger.debug("OTel metrics initialised.")
        except Exception as exc:
            logger.warning("Failed to initialise OTel metrics: %s", exc)

    # ------------------------------------------------------------------
    # Span lifecycle
    # ------------------------------------------------------------------

    def start_span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
    ) -> SpanInfo:
        """
        Create and start a new span.

        Args:
            name: Human-readable span name.
            attributes: Key/value pairs attached to the span.
            trace_id: Optional explicit trace ID (hex string). If ``None``,
                      one is generated automatically.
            parent_span_id: Optional parent span ID for linking.

        Returns:
            A ``SpanInfo`` object that can be used to add events, set status,
            and must be ended via ``span.end()``.
        """
        attrs = attributes or {}
        generated_trace_id = trace_id or uuid.uuid4().hex
        generated_span_id = uuid.uuid4().hex[:16]

        otel_span = None

        if self._otel_available and self._tracer is not None:
            try:
                # Build optional parent context
                ctx = None
                if parent_span_id and parent_span_id in self._active_spans:
                    parent_info = self._active_spans[parent_span_id]
                    if parent_info._otel_span is not None:
                        ctx = set_span_in_context(parent_info._otel_span)

                otel_span = self._tracer.start_span(
                    name=name,
                    attributes=attrs,
                    kind=SpanKind.INTERNAL,
                    context=ctx,
                )

                # Extract real IDs from the OTel span
                span_ctx = otel_span.get_span_context()
                if span_ctx and span_ctx.trace_id:
                    generated_trace_id = format(span_ctx.trace_id, "032x")
                    generated_span_id = format(span_ctx.span_id, "016x")

            except Exception as exc:
                logger.warning("Failed to start OTel span: %s", exc)
                otel_span = None

        span_info = SpanInfo(
            trace_id=generated_trace_id,
            span_id=generated_span_id,
            name=name,
            start_time=time.time(),
            attributes=attrs,
            _otel_span=otel_span,
        )

        self._active_spans[generated_span_id] = span_info
        self._span_count += 1

        self.event_counter.add(1, {"span.name": name})

        return span_info

    def end_span(self, span: SpanInfo) -> None:
        """End a span and remove it from the active set."""
        span.end()
        self._active_spans.pop(span.span_id, None)

    # ------------------------------------------------------------------
    # W3C context propagation
    # ------------------------------------------------------------------

    def inject_context(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Inject W3C ``traceparent`` and ``tracestate`` headers for outbound
        propagation.

        Args:
            headers: Mutable dict of HTTP headers. Modified in-place and
                     also returned for convenience.

        Returns:
            The (possibly modified) headers dict.
        """
        if self._otel_available:
            try:
                from opentelemetry.propagate import inject

                inject(headers)
                return headers
            except Exception as exc:
                logger.warning("Context injection failed: %s", exc)

        # Fallback: manually construct traceparent from the most recent span
        if self._active_spans:
            latest = list(self._active_spans.values())[-1]
            traceparent = (
                f"00-{latest.trace_id.zfill(32)}-{latest.span_id.zfill(16)}-01"
            )
            headers["traceparent"] = traceparent

        return headers

    def extract_context(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Extract W3C trace context from incoming headers.

        Args:
            headers: Incoming HTTP headers (or carrier dict).

        Returns:
            A dict with ``trace_id``, ``span_id``, and ``trace_flags`` if
            successfully parsed, or ``None``.
        """
        if self._otel_available:
            try:
                from opentelemetry.propagate import extract

                ctx = extract(headers)
                span = get_current_span(ctx)
                if span and hasattr(span, "get_span_context"):
                    sc = span.get_span_context()
                    if sc and sc.trace_id:
                        return {
                            "trace_id": format(sc.trace_id, "032x"),
                            "span_id": format(sc.span_id, "016x"),
                            "trace_flags": format(sc.trace_flags, "02x"),
                        }
            except Exception as exc:
                logger.warning("Context extraction failed: %s", exc)

        # Fallback: parse traceparent manually
        traceparent = headers.get("traceparent", "")
        if traceparent:
            parts = traceparent.split("-")
            if len(parts) >= 4:
                return {
                    "trace_id": parts[1],
                    "span_id": parts[2],
                    "trace_flags": parts[3],
                }

        return None

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    def trace_event(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add ``trace_id`` and ``span_id`` to an event dict for correlation.

        If there is an active span, its identifiers are used. Otherwise new
        identifiers are generated.

        Args:
            event_dict: Mutable event dictionary. Modified in-place.

        Returns:
            The modified event dict.
        """
        if self._active_spans:
            latest = list(self._active_spans.values())[-1]
            event_dict["trace_id"] = latest.trace_id
            event_dict["span_id"] = latest.span_id
        else:
            event_dict.setdefault("trace_id", uuid.uuid4().hex)
            event_dict.setdefault("span_id", uuid.uuid4().hex[:16])

        event_dict.setdefault("correlation_id", self.create_correlation_id())
        return event_dict

    def create_correlation_id(self) -> str:
        """
        Generate a correlation ID that can link events across systems.

        Format: ``vestigia-<timestamp_ms>-<random_hex>``
        """
        ts = int(time.time() * 1000)
        rand = uuid.uuid4().hex[:12]
        return f"vestigia-{ts}-{rand}"

    # ------------------------------------------------------------------
    # Decorator
    # ------------------------------------------------------------------

    def traced(self, name: Optional[str] = None) -> Callable[[F], F]:
        """
        Decorator factory for auto-tracing functions.

        Usage::

            tracer = VestigiaTracer()

            @tracer.traced("my_operation")
            def do_work(x, y):
                return x + y

        Args:
            name: Span name. Defaults to the decorated function's ``__qualname__``.
        """
        tracer = self

        def decorator(func: F) -> F:
            span_name = name or func.__qualname__

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                span = tracer.start_span(
                    span_name,
                    attributes={
                        "function": func.__qualname__,
                        "module": func.__module__,
                    },
                )
                start = time.time()
                try:
                    result = func(*args, **kwargs)
                    span.set_status_ok()
                    return result
                except Exception as exc:
                    span.set_status_error(str(exc))
                    tracer.error_counter.add(
                        1, {"function": func.__qualname__, "error": type(exc).__name__}
                    )
                    raise
                finally:
                    elapsed_ms = (time.time() - start) * 1000
                    tracer.ingestion_latency_histogram.record(
                        elapsed_ms, {"function": func.__qualname__}
                    )
                    tracer.end_span(span)

            return wrapper  # type: ignore[return-value]

        return decorator

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Flush pending spans and shut down the provider."""
        if self._provider is not None:
            try:
                self._provider.shutdown()
                logger.info("VestigiaTracer shut down.")
            except Exception as exc:
                logger.warning("Error during tracer shutdown: %s", exc)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return basic tracer statistics."""
        return {
            "otel_available": self._otel_available,
            "service_name": self.service_name,
            "endpoint": self.endpoint,
            "total_spans_created": self._span_count,
            "active_spans": len(self._active_spans),
        }


# ---------------------------------------------------------------------------
# Module-level convenience: a default ``traced`` decorator
# ---------------------------------------------------------------------------

_default_tracer: Optional[VestigiaTracer] = None


def traced(name: Optional[str] = None) -> Callable[[F], F]:
    """
    Module-level ``@traced`` decorator using a lazily-created default tracer.

    Usage::

        from core.otel_integration import traced

        @traced("process_event")
        def process_event(event):
            ...
    """
    global _default_tracer
    if _default_tracer is None:
        _default_tracer = VestigiaTracer()
    return _default_tracer.traced(name)


# ---------------------------------------------------------------------------
# Self-test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    print("=" * 70)
    print("  Vestigia OTel Integration - Self Test")
    print("=" * 70)

    tracer = VestigiaTracer(service_name="vestigia-test")
    print(f"\nOTel available: {tracer._otel_available}")
    print(f"Stats: {tracer.get_stats()}")

    # -- Start a span --
    span = tracer.start_span(
        "test_operation",
        attributes={"test.key": "test_value", "severity": "INFO"},
    )
    print(f"\nStarted span: trace_id={span.trace_id}, span_id={span.span_id}")

    # -- Trace an event dict --
    event = {"action": "LOGIN", "actor": "agent_001"}
    tracer.trace_event(event)
    print(f"Traced event: {event}")

    # -- Inject context --
    headers: Dict[str, str] = {}
    tracer.inject_context(headers)
    print(f"Injected headers: {headers}")

    # -- Extract context --
    extracted = tracer.extract_context(headers)
    print(f"Extracted context: {extracted}")

    # -- Correlation ID --
    corr = tracer.create_correlation_id()
    print(f"Correlation ID: {corr}")

    # -- End span --
    span.set_status_ok()
    tracer.end_span(span)
    print(f"Span ended. Active spans: {len(tracer._active_spans)}")

    # -- Decorator --
    @tracer.traced("demo_function")
    def demo_add(a: int, b: int) -> int:
        """Demo traced function."""
        return a + b

    result = demo_add(3, 7)
    print(f"\nTraced function result: {result}")

    # -- Metrics stubs --
    tracer.event_counter.add(1, {"source": "test"})
    tracer.error_counter.add(1, {"source": "test"})
    tracer.ingestion_latency_histogram.record(42.5, {"source": "test"})
    print("Metrics recorded (or no-op'd).")

    # -- Shutdown --
    tracer.shutdown()
    print(f"\nFinal stats: {tracer.get_stats()}")
    print("\n[PASS] OTel integration self-test complete.")

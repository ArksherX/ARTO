#!/usr/bin/env python3
"""
VerityFlux Enterprise - Observability Module
Prometheus metrics, health checks, and telemetry

This module provides:
- Prometheus metrics endpoint (/metrics)
- Request/response timing middleware
- Business metrics (approvals, scans, events)
- Health check endpoints with detailed status
"""

import time
import logging
from typing import Callable, Dict, Any, Optional
from functools import wraps
from dataclasses import dataclass, field
from collections import defaultdict
import threading

logger = logging.getLogger("verityflux.observability")


# =============================================================================
# METRICS REGISTRY
# =============================================================================

class MetricsRegistry:
    """
    Simple Prometheus-compatible metrics registry.
    Thread-safe for concurrent access.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._gauges: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._histograms: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        self._histogram_buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    
    def _labels_to_key(self, labels: Dict[str, str]) -> str:
        """Convert labels dict to a string key."""
        if not labels:
            return ""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    
    def counter_inc(self, name: str, value: float = 1, labels: Dict[str, str] = None):
        """Increment a counter."""
        with self._lock:
            key = self._labels_to_key(labels or {})
            self._counters[name][key] += value
    
    def gauge_set(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge value."""
        with self._lock:
            key = self._labels_to_key(labels or {})
            self._gauges[name][key] = value
    
    def gauge_inc(self, name: str, value: float = 1, labels: Dict[str, str] = None):
        """Increment a gauge."""
        with self._lock:
            key = self._labels_to_key(labels or {})
            self._gauges[name][key] += value
    
    def gauge_dec(self, name: str, value: float = 1, labels: Dict[str, str] = None):
        """Decrement a gauge."""
        with self._lock:
            key = self._labels_to_key(labels or {})
            self._gauges[name][key] -= value
    
    def histogram_observe(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram observation."""
        with self._lock:
            key = self._labels_to_key(labels or {})
            self._histograms[name][key].append(value)
    
    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus text format."""
        lines = []
        
        with self._lock:
            # Export counters
            for name, values in self._counters.items():
                lines.append(f"# TYPE {name} counter")
                for labels_key, value in values.items():
                    if labels_key:
                        lines.append(f"{name}{{{labels_key}}} {value}")
                    else:
                        lines.append(f"{name} {value}")
            
            # Export gauges
            for name, values in self._gauges.items():
                lines.append(f"# TYPE {name} gauge")
                for labels_key, value in values.items():
                    if labels_key:
                        lines.append(f"{name}{{{labels_key}}} {value}")
                    else:
                        lines.append(f"{name} {value}")
            
            # Export histograms
            for name, values in self._histograms.items():
                lines.append(f"# TYPE {name} histogram")
                for labels_key, observations in values.items():
                    if not observations:
                        continue
                    
                    # Calculate bucket counts
                    sorted_obs = sorted(observations)
                    total = len(sorted_obs)
                    sum_val = sum(sorted_obs)
                    
                    bucket_counts = []
                    obs_idx = 0
                    for bucket in self._histogram_buckets:
                        while obs_idx < total and sorted_obs[obs_idx] <= bucket:
                            obs_idx += 1
                        bucket_counts.append((bucket, obs_idx))
                    bucket_counts.append(("+Inf", total))
                    
                    # Output buckets
                    for bucket, count in bucket_counts:
                        if labels_key:
                            lines.append(f'{name}_bucket{{{labels_key},le="{bucket}"}} {count}')
                        else:
                            lines.append(f'{name}_bucket{{le="{bucket}"}} {count}')
                    
                    # Output sum and count
                    if labels_key:
                        lines.append(f"{name}_sum{{{labels_key}}} {sum_val}")
                        lines.append(f"{name}_count{{{labels_key}}} {total}")
                    else:
                        lines.append(f"{name}_sum {sum_val}")
                        lines.append(f"{name}_count {total}")
        
        return "\n".join(lines) + "\n"
    
    def get_metrics_dict(self) -> Dict[str, Any]:
        """Get metrics as a dictionary (for JSON export)."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    name: {
                        key: {
                            "count": len(vals),
                            "sum": sum(vals) if vals else 0,
                            "min": min(vals) if vals else 0,
                            "max": max(vals) if vals else 0,
                            "avg": sum(vals) / len(vals) if vals else 0,
                        }
                        for key, vals in values.items()
                    }
                    for name, values in self._histograms.items()
                },
            }


# Global metrics registry
metrics = MetricsRegistry()


# =============================================================================
# PREDEFINED METRICS
# =============================================================================

# Request metrics
REQUEST_COUNT = "verityflux_http_requests_total"
REQUEST_LATENCY = "verityflux_http_request_duration_seconds"
REQUEST_IN_PROGRESS = "verityflux_http_requests_in_progress"

# Business metrics
AGENTS_REGISTERED = "verityflux_agents_registered_total"
AGENTS_ACTIVE = "verityflux_agents_active"
EVENTS_PROCESSED = "verityflux_events_processed_total"
APPROVALS_CREATED = "verityflux_approvals_created_total"
APPROVALS_DECIDED = "verityflux_approvals_decided_total"
SCANS_COMPLETED = "verityflux_scans_completed_total"
ALERTS_CREATED = "verityflux_alerts_created_total"
INCIDENTS_CREATED = "verityflux_incidents_created_total"

# System metrics
DB_CONNECTIONS_ACTIVE = "verityflux_db_connections_active"
CACHE_HITS = "verityflux_cache_hits_total"
CACHE_MISSES = "verityflux_cache_misses_total"


# =============================================================================
# FASTAPI MIDDLEWARE
# =============================================================================

class PrometheusMiddleware:
    """
    FastAPI middleware for automatic request metrics.
    
    Usage:
        from fastapi import FastAPI
        from verityflux_enterprise.core.observability import PrometheusMiddleware
        
        app = FastAPI()
        app.add_middleware(PrometheusMiddleware)
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Extract request info
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        
        # Normalize path (remove IDs for better grouping)
        normalized_path = self._normalize_path(path)
        
        labels = {"method": method, "path": normalized_path}
        
        # Track in-progress requests
        metrics.gauge_inc(REQUEST_IN_PROGRESS, labels=labels)
        
        start_time = time.time()
        status_code = 500  # Default in case of error
        
        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
            await send(message)
        
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Record metrics
            duration = time.time() - start_time
            
            labels_with_status = {**labels, "status": str(status_code)}
            
            metrics.counter_inc(REQUEST_COUNT, labels=labels_with_status)
            metrics.histogram_observe(REQUEST_LATENCY, duration, labels=labels)
            metrics.gauge_dec(REQUEST_IN_PROGRESS, labels=labels)
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing IDs with placeholders."""
        import re
        # Replace UUIDs
        path = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{id}', path)
        # Replace numeric IDs
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
        return path


def create_metrics_endpoint():
    """
    Create a FastAPI router for metrics endpoints.
    
    Usage:
        from fastapi import FastAPI
        from verityflux_enterprise.core.observability import create_metrics_endpoint
        
        app = FastAPI()
        app.include_router(create_metrics_endpoint())
    """
    from fastapi import APIRouter, Response
    
    router = APIRouter(tags=["Observability"])
    
    @router.get("/metrics", response_class=Response)
    async def prometheus_metrics():
        """Prometheus metrics endpoint."""
        return Response(
            content=metrics.export_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8"
        )
    
    @router.get("/metrics/json")
    async def json_metrics():
        """JSON metrics endpoint for debugging."""
        return metrics.get_metrics_dict()
    
    return router


# =============================================================================
# BUSINESS METRICS HELPERS
# =============================================================================

def record_agent_registered(agent_type: str = "unknown"):
    """Record a new agent registration."""
    metrics.counter_inc(AGENTS_REGISTERED, labels={"type": agent_type})
    metrics.gauge_inc(AGENTS_ACTIVE, labels={"type": agent_type})


def record_agent_deactivated(agent_type: str = "unknown"):
    """Record agent deactivation."""
    metrics.gauge_dec(AGENTS_ACTIVE, labels={"type": agent_type})


def record_event_processed(event_type: str, severity: str, decision: str):
    """Record a processed security event."""
    metrics.counter_inc(EVENTS_PROCESSED, labels={
        "type": event_type,
        "severity": severity,
        "decision": decision,
    })


def record_approval_created(risk_level: str):
    """Record a new approval request."""
    metrics.counter_inc(APPROVALS_CREATED, labels={"risk_level": risk_level})


def record_approval_decided(decision: str, auto: bool = False):
    """Record an approval decision."""
    metrics.counter_inc(APPROVALS_DECIDED, labels={
        "decision": decision,
        "auto": str(auto).lower(),
    })


def record_scan_completed(profile: str, risk_level: str):
    """Record a completed scan."""
    metrics.counter_inc(SCANS_COMPLETED, labels={
        "profile": profile,
        "risk_level": risk_level,
    })


def record_alert_created(severity: str):
    """Record a new alert."""
    metrics.counter_inc(ALERTS_CREATED, labels={"severity": severity})


def record_incident_created(priority: str):
    """Record a new incident."""
    metrics.counter_inc(INCIDENTS_CREATED, labels={"priority": priority})


# =============================================================================
# TIMING DECORATOR
# =============================================================================

def timed(metric_name: str, labels: Dict[str, str] = None):
    """
    Decorator to time function execution.
    
    Usage:
        @timed("verityflux_scan_duration_seconds", {"type": "deep"})
        async def run_deep_scan():
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return await func(*args, **kwargs)
            finally:
                duration = time.time() - start
                metrics.histogram_observe(metric_name, duration, labels=labels)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.time() - start
                metrics.histogram_observe(metric_name, duration, labels=labels)
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# =============================================================================
# HEALTH CHECK DETAILS
# =============================================================================

@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    healthy: bool
    message: str = ""
    latency_ms: float = 0
    details: Dict[str, Any] = field(default_factory=dict)


class HealthChecker:
    """
    Comprehensive health checker for all system components.
    """
    
    def __init__(self):
        self.checks: Dict[str, Callable] = {}
    
    def register(self, name: str, check_func: Callable):
        """Register a health check function."""
        self.checks[name] = check_func
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all health checks and return results."""
        results = []
        overall_healthy = True
        
        for name, check_func in self.checks.items():
            start = time.time()
            try:
                import asyncio
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()
                
                latency = (time.time() - start) * 1000
                
                if isinstance(result, bool):
                    results.append(HealthCheckResult(
                        name=name,
                        healthy=result,
                        latency_ms=latency,
                    ))
                elif isinstance(result, HealthCheckResult):
                    result.latency_ms = latency
                    results.append(result)
                else:
                    results.append(HealthCheckResult(
                        name=name,
                        healthy=True,
                        message=str(result),
                        latency_ms=latency,
                    ))
                    
            except Exception as e:
                latency = (time.time() - start) * 1000
                results.append(HealthCheckResult(
                    name=name,
                    healthy=False,
                    message=str(e),
                    latency_ms=latency,
                ))
            
            if not results[-1].healthy:
                overall_healthy = False
        
        return {
            "healthy": overall_healthy,
            "checks": [
                {
                    "name": r.name,
                    "healthy": r.healthy,
                    "message": r.message,
                    "latency_ms": round(r.latency_ms, 2),
                    "details": r.details,
                }
                for r in results
            ],
        }


# Global health checker
health_checker = HealthChecker()


# Register default checks
def check_memory():
    """Check memory usage."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        healthy = mem.percent < 90
        return HealthCheckResult(
            name="memory",
            healthy=healthy,
            message=f"{mem.percent}% used",
            details={"percent": mem.percent, "available_gb": round(mem.available / 1e9, 2)},
        )
    except ImportError:
        return HealthCheckResult(name="memory", healthy=True, message="psutil not available")


def check_disk():
    """Check disk usage."""
    try:
        import psutil
        disk = psutil.disk_usage("/")
        healthy = disk.percent < 90
        return HealthCheckResult(
            name="disk",
            healthy=healthy,
            message=f"{disk.percent}% used",
            details={"percent": disk.percent, "free_gb": round(disk.free / 1e9, 2)},
        )
    except ImportError:
        return HealthCheckResult(name="disk", healthy=True, message="psutil not available")


health_checker.register("memory", check_memory)
health_checker.register("disk", check_disk)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Registry
    "MetricsRegistry",
    "metrics",
    # Middleware
    "PrometheusMiddleware",
    "create_metrics_endpoint",
    # Business metrics
    "record_agent_registered",
    "record_agent_deactivated",
    "record_event_processed",
    "record_approval_created",
    "record_approval_decided",
    "record_scan_completed",
    "record_alert_created",
    "record_incident_created",
    # Utilities
    "timed",
    # Health checks
    "HealthCheckResult",
    "HealthChecker",
    "health_checker",
]

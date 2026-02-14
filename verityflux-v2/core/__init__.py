"""
VerityFlux Enterprise - Core Package

This package contains the core functionality of VerityFlux:
- Authentication & Authorization
- Database Models & Migrations  
- Human-in-the-Loop (HITL) Approval System
- SOC Command Center
- Security Scanner
- Vulnerability Database
- Observability & Metrics
- Rate Limiting
"""

__version__ = "3.5.0"

# Import core modules (with fallbacks for missing dependencies)
try:
    from .observability import (
        MetricsRegistry,
        metrics,
        PrometheusMiddleware,
        create_metrics_endpoint,
        record_agent_registered,
        record_event_processed,
        record_approval_created,
        record_approval_decided,
        record_scan_completed,
        record_alert_created,
        timed,
        HealthChecker,
        health_checker,
    )
    OBSERVABILITY_AVAILABLE = True
except ImportError:
    OBSERVABILITY_AVAILABLE = False

try:
    from .rate_limiting import (
        RateLimitConfig,
        InMemoryRateLimiter,
        RedisRateLimiter,
        RateLimitMiddleware,
        rate_limit,
    )
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False

__all__ = [
    "__version__",
    "OBSERVABILITY_AVAILABLE",
    "RATE_LIMITING_AVAILABLE",
]

if OBSERVABILITY_AVAILABLE:
    __all__.extend([
        "MetricsRegistry",
        "metrics",
        "PrometheusMiddleware",
        "create_metrics_endpoint",
        "record_agent_registered",
        "record_event_processed",
        "record_approval_created",
        "record_approval_decided",
        "record_scan_completed",
        "record_alert_created",
        "timed",
        "HealthChecker",
        "health_checker",
    ])

if RATE_LIMITING_AVAILABLE:
    __all__.extend([
        "RateLimitConfig",
        "InMemoryRateLimiter",
        "RedisRateLimiter",
        "RateLimitMiddleware",
        "rate_limit",
    ])

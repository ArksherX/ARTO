#!/usr/bin/env python3
"""
Vestigia API Server - FastAPI Event Ingestion
Production-grade REST API for the Vestigia audit system.
"""

import os
import sys
import time
import logging
import uuid
import json
import base64
import hashlib
from datetime import datetime, UTC, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Header,
    Query,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Path bootstrap -- ensure project root is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from core.ledger_engine import VestigiaLedger, StructuredEvidence
from validator import VestigiaValidator
from core.access_audit import AccessAuditLogger
from core.blockchain_anchor import BlockchainAnchor
from core.anomaly_detection import AnomalyDetector
from core.resilient_siem_forwarder import ResilientSIEMForwarder
from core.nl_query import NLQueryEngine
from core.playbook_engine import PlaybookEngine
from core.risk_forecasting import RiskHistoryStore, RiskForecaster
from core.tenant_manager import TenantStore, TenantContext, ROLE_PERMISSIONS, PLAN_LIMITS
from core.ops_health import collect_health

try:
    from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

    def _counter(name: str, desc: str):
        try:
            return Counter(name, desc)
        except ValueError:
            # Reload-safe in dev: reuse collector if already registered.
            return REGISTRY._names_to_collectors.get(name)
except Exception:
    Counter = generate_latest = CONTENT_TYPE_LATEST = None

    def _counter(name: str, desc: str):
        return None

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vestigia.api")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_VERSION = "2.5"
API_KEY = os.getenv("VESTIGIA_API_KEY", "")
DB_DSN = os.getenv("VESTIGIA_DB_DSN", "")
LEDGER_PATH = os.getenv("VESTIGIA_LEDGER_PATH", "data/vestigia_ledger.json")
ANCHOR_PROVIDER = os.getenv("VESTIGIA_BLOCKCHAIN_PROVIDER", "file")
MULTI_TENANT = os.getenv("VESTIGIA_MULTI_TENANT", "false").lower() == "true"
PLATFORM_ADMIN_KEY = os.getenv("VESTIGIA_PLATFORM_ADMIN_KEY", "")
REDIS_URL = os.getenv("VESTIGIA_REDIS_URL", "")
MLRT_ENFORCE_CONTRACT = os.getenv("MLRT_ENFORCE_CONTRACT", "false").lower() in ("1", "true", "yes")
MLRT_REQUIRE_CORRELATION = os.getenv("MLRT_REQUIRE_CORRELATION", "false").lower() in ("1", "true", "yes")
MLRT_CONTRACT_VERSION = os.getenv("MLRT_CONTRACT_VERSION", "1")

# ---------------------------------------------------------------------------
# Rate-limiter -- simple in-memory token bucket
# ---------------------------------------------------------------------------

class TokenBucket:
    """Per-token rate limiter using the token-bucket algorithm."""

    def __init__(self, rate: float = 10.0, capacity: float = 20.0):
        self.rate = rate          # tokens added per second
        self.capacity = capacity  # max burst
        self._buckets: Dict[str, tuple] = {}  # key -> (tokens, last_ts)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (self.capacity, now))
        elapsed = now - last
        tokens = min(self.capacity, tokens + elapsed * self.rate)
        if tokens < 1.0:
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True


rate_limiter = TokenBucket(rate=10.0, capacity=20.0)

# ---------------------------------------------------------------------------
# Pydantic models -- Request
# ---------------------------------------------------------------------------

class EventCreateRequest(BaseModel):
    actor_id: str = Field(..., min_length=1, description="Identifier of the actor producing the event")
    action_type: str = Field(..., min_length=1, description="Type of action (e.g. SECURITY_SCAN)")
    status: str = Field(..., min_length=1, description="Event status (SUCCESS, BLOCKED, CRITICAL, ...)")
    evidence: Dict[str, Any] = Field(..., description="Structured evidence payload")
    severity: Optional[str] = Field(None, description="Optional severity override")
    trace_id: Optional[str] = Field(None, description="OpenTelemetry trace ID")
    span_id: Optional[str] = Field(None, description="OpenTelemetry span ID")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Arbitrary extra metadata")


class EvidenceVerifyRequest(BaseModel):
    payload: Dict[str, Any] = Field(..., description="Original evidence payload")
    signature: str = Field(..., description="Base64url signature over canonical payload")
    public_key: str = Field(..., description="Public key PEM")
    expected_hash: Optional[str] = Field(None, description="Optional expected SHA-256 hash")


class BatchEventRequest(BaseModel):
    events: List[EventCreateRequest] = Field(..., min_length=1, description="List of events to ingest")


class SIEMWebhookRequest(BaseModel):
    source: str = Field(..., description="SIEM source identifier")
    alert_id: str = Field(..., description="Alert identifier from the SIEM")
    severity: str = Field(..., description="Alert severity")
    description: str = Field(..., description="Human-readable alert description")
    affected_events: Optional[List[str]] = Field(
        default=None, description="List of Vestigia event IDs related to this alert"
    )

# ---------------------------------------------------------------------------
# Pydantic models -- Response
# ---------------------------------------------------------------------------

class EventResponse(BaseModel):
    event_id: str
    integrity_hash: str
    timestamp: str
    status: str = "recorded"


class EventDetailResponse(BaseModel):
    timestamp: str
    actor_id: str
    action_type: str
    status: str
    evidence: Any
    integrity_hash: str
    event_id: str
    previous_hash: str
    severity: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class EventListResponse(BaseModel):
    events: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


class BatchEventResponse(BaseModel):
    recorded: int
    failed: int
    events: List[EventResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    total_events: int
    ledger_valid: bool


class IntegrityResponse(BaseModel):
    is_valid: bool
    total_entries: int
    issues: List[Dict[str, Any]]


class SIEMWebhookResponse(BaseModel):
    status: str
    enriched_event_id: str
    matched_events: int


class ExportResponse(BaseModel):
    exported: int
    status: str


class AnomalyScoreRequest(BaseModel):
    actor_id: str
    action_type: str
    status: str
    evidence: Dict[str, Any]


class AnomalyScoreResponse(BaseModel):
    risk_score: float
    signals: List[str]


class AnomalyFeedbackRequest(BaseModel):
    event_id: str
    actor_id: str
    note: Optional[str] = None


class NLQueryRequest(BaseModel):
    query: str
    limit: int = Field(200, ge=1, le=2000)


class NLQueryResponse(BaseModel):
    filters: Dict[str, Any]
    post_filters: Dict[str, Any]
    results: List[Dict[str, Any]]
    total: int


class PlaybookExecuteRequest(BaseModel):
    name: str
    actor_id: Optional[str] = None
    action_type: Optional[str] = None
    status: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0


class PlaybookExecuteResponse(BaseModel):
    playbook_name: str
    executed_at: str
    details: Dict[str, Any]


class RiskForecastResponse(BaseModel):
    actor_id: str
    forecast_horizon: str
    predicted_risk: float
    confidence_interval: List[float]
    recommendation: str


class TenantCreateRequest(BaseModel):
    name: str
    plan: str = "free"
    admin_email: str


class TenantCreateResponse(BaseModel):
    tenant_id: str
    name: str
    plan: str
    admin_user_id: str
    api_key: str


class TenantUserCreateRequest(BaseModel):
    email: str
    role: str = "viewer"


class ApiKeyCreateRequest(BaseModel):
    user_id: str
    label: str = "default"


class ApiKeyCreateResponse(BaseModel):
    key_id: str
    api_key: str
    label: str


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _verify_ed25519(public_key_pem: str, payload: Dict[str, Any], signature: str) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(_b64url_decode(signature), _canonical_bytes(payload))
        return True
    except Exception:
        return False


def _validate_contract_event(contract_event: Dict[str, Any]) -> Optional[str]:
    required = ("timestamp", "source", "event_type", "outcome")
    for key in required:
        if key not in contract_event:
            return f"contract_event missing required field: {key}"
    if not isinstance(contract_event.get("outcome"), dict):
        return "contract_event.outcome must be an object"
    if "status" not in contract_event["outcome"]:
        return "contract_event.outcome.status is required"
    version = str(contract_event.get("event_schema_version", MLRT_CONTRACT_VERSION))
    if version != str(MLRT_CONTRACT_VERSION):
        return f"unsupported contract_event.event_schema_version: {version}"
    return None


def _require_correlation_fields(contract_event: Dict[str, Any]) -> Optional[str]:
    actor = contract_event.get("actor") or {}
    req = contract_event.get("request") or {}
    if not actor.get("agent_id"):
        return "contract_event.actor.agent_id is required when correlation enforcement is enabled"
    if not req.get("session_id"):
        return "contract_event.request.session_id is required when correlation enforcement is enabled"
    if not req.get("trace_id"):
        return "contract_event.request.trace_id is required when correlation enforcement is enabled"
    return None


def _backfill_contract_correlation(contract_event: Dict[str, Any], fallback_actor: str) -> Dict[str, Any]:
    actor = contract_event.get("actor") or {}
    req = contract_event.get("request") or {}
    agent_id = actor.get("agent_id") or fallback_actor or "unknown"
    event_type = contract_event.get("event_type") or "event"
    session_id = req.get("session_id") or f"{agent_id}:{event_type}"
    trace_id = req.get("trace_id") or session_id
    req["session_id"] = session_id
    req["trace_id"] = trace_id
    actor["agent_id"] = agent_id
    contract_event["actor"] = actor
    contract_event["request"] = req
    return contract_event

# ---------------------------------------------------------------------------
# Application factory helpers
# ---------------------------------------------------------------------------

_startup_time: float = 0.0
_ledger: Optional[VestigiaLedger] = None
_access_audit = AccessAuditLogger(DB_DSN)
_blockchain_anchor = None
_anomaly_detector = AnomalyDetector()
_nl_query_engine = NLQueryEngine()
_playbook_engine = PlaybookEngine()
_risk_history = RiskHistoryStore()
_risk_forecaster = RiskForecaster(store=_risk_history)
_tenant_store = TenantStore()
_siem_forwarder = None
_metric_anomaly_scored = _counter("vestigia_anomaly_scored_total", "Anomaly scores computed")
_metric_anomaly_alerts = _counter("vestigia_anomaly_alerts_total", "High-risk anomaly alerts")
_metric_playbooks = _counter("vestigia_playbooks_executed_total", "Playbooks executed")
_metric_nl_queries = _counter("vestigia_nl_queries_total", "Natural language queries executed")
_metric_risk_forecasts = _counter("vestigia_risk_forecasts_total", "Risk forecasts generated")
_last_integrity_check_ts: float = 0.0
_last_integrity_ok: bool = True


def _get_ledger() -> VestigiaLedger:
    """Return the global ledger instance, lazily initialised."""
    global _ledger
    if _ledger is None:
        _ledger = VestigiaLedger(
            ledger_path=LEDGER_PATH,
            enable_merkle_witness=True,
            enable_external_anchor=False,
        )
    return _ledger


def _get_blockchain_anchor() -> BlockchainAnchor:
    global _blockchain_anchor
    if _blockchain_anchor is None:
        _blockchain_anchor = BlockchainAnchor(provider=ANCHOR_PROVIDER)
    return _blockchain_anchor


def _get_siem_forwarder() -> Optional[ResilientSIEMForwarder]:
    global _siem_forwarder
    if _siem_forwarder is None:
        targets_json = os.getenv("VESTIGIA_SIEM_TARGETS", "[]")
        try:
            targets = json.loads(targets_json)
        except Exception:
            targets = []
        if targets:
            _siem_forwarder = ResilientSIEMForwarder(targets=targets)
            _siem_forwarder.start()
    return _siem_forwarder


def _require_api_key(request: Request, authorization: Optional[str] = Header(None)) -> Optional[TenantContext]:
    """Dependency that validates Bearer tokens for single or multi-tenant modes."""
    if MULTI_TENANT:
        if authorization is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
            )
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization scheme",
            )
        ctx = _tenant_store.authenticate(token)
        if not ctx:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        request.state.tenant_id = ctx.tenant_id
        request.state.role = ctx.role
        request.state.user_id = ctx.user_id
        request.state.tenant_ctx = ctx
        return ctx

    if not API_KEY:
        # No key configured -- allow all requests (development mode)
        return None
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token",
        )
    return None


def _require_permission(permission: str):
    def _check(request: Request):
        if not MULTI_TENANT:
            return
        ctx = getattr(request.state, "tenant_ctx", None)
        if not ctx:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant context")
        if not ctx.can(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role permissions")
    return _check


def _require_platform_admin(x_platform_admin: Optional[str] = Header(None, alias="X-Platform-Admin")):
    if not PLATFORM_ADMIN_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Platform admin key not configured")
    if x_platform_admin != PLATFORM_ADMIN_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid platform admin key")


def _require_same_tenant(request: Request, tenant_id: str):
    if not MULTI_TENANT:
        return
    ctx = getattr(request.state, "tenant_ctx", None)
    if not ctx or ctx.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant scope violation")


def _enforce_plan_limit(tenant_id: Optional[str], events_to_add: int = 1):
    if not MULTI_TENANT or not tenant_id:
        return
    limits = _tenant_store.get_plan_limits(tenant_id)
    current = _tenant_store.get_usage(tenant_id)
    if current + events_to_add > limits.get("events_per_day", 0):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Plan limit exceeded: events per day",
        )


def _rate_limit(request: Request):
    """Dependency that enforces rate limiting per client IP."""
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please retry later.",
        )


def _get_user_id(request: Request) -> str:
    return request.headers.get("X-User-ID") or "api_key"


def _log_access(request: Request, query_text: str, rows_accessed: int):
    user_id = _get_user_id(request)
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "")
    alert = _access_audit.is_suspicious(rows_accessed)
    _access_audit.log_access(user_id, query_text, rows_accessed, ip_address, user_agent, alert_triggered=alert)
    if alert:
        try:
            ledger = _get_ledger()
            ledger.append_event(
                actor_id="access_audit",
                action_type="ACCESS_ALERT",
                status="WARNING",
                evidence={
                    "summary": "Suspicious access pattern detected",
                    "user_id": user_id,
                    "rows_accessed": rows_accessed,
                    "path": request.url.path,
                },
            )
        except Exception:
            logger.exception("Failed to log access alert")

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Vestigia API",
    description="Production-grade event ingestion and audit ledger API for the Vestigia system.",
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# -- CORS middleware --------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- Request-logging middleware ---------------------------------------------

@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log every request into the Vestigia ledger itself and propagate
    OpenTelemetry trace-context headers."""
    start = time.monotonic()
    response = await call_next(request)
    elapsed = time.monotonic() - start

    # Best-effort ledger logging -- never let logging failures break responses
    try:
        ledger = _get_ledger()
        traceparent = request.headers.get("traceparent", "")
        tracestate = request.headers.get("tracestate", "")
        ledger.append_event(
            actor_id="api_server",
            action_type="API_REQUEST",
            status="SUCCESS" if response.status_code < 400 else "WARNING",
            evidence={
                "summary": f"{request.method} {request.url.path}",
                "method": request.method,
                "path": str(request.url.path),
                "status_code": response.status_code,
                "elapsed_ms": round(elapsed * 1000, 2),
                "client": request.client.host if request.client else "unknown",
                "traceparent": traceparent,
                "tracestate": tracestate,
            },
        )
    except Exception:
        logger.exception("Failed to log request to ledger")

    # Propagate trace-context headers from the inbound request
    traceparent = request.headers.get("traceparent")
    tracestate = request.headers.get("tracestate")
    if traceparent:
        response.headers["traceparent"] = traceparent
    if tracestate:
        response.headers["tracestate"] = tracestate

    return response

# -- Lifecycle events -------------------------------------------------------

@app.on_event("startup")
async def on_startup():
    global _startup_time
    _startup_time = time.monotonic()

    logger.info("Vestigia API Server starting up (v%s)", API_VERSION)

    # Initialise ledger
    ledger = _get_ledger()
    logger.info("Ledger loaded from %s", LEDGER_PATH)

    # Backend info
    if DB_DSN:
        logger.info("PostgreSQL backend configured (DSN set)")
    else:
        logger.info("Using JSON file backend at %s", LEDGER_PATH)

    # Initial integrity check
    is_valid, broken_idx = ledger.verify_integrity()
    if is_valid:
        logger.info("Initial integrity check PASSED")
    else:
        logger.warning("Initial integrity check FAILED at index %s", broken_idx)

    # Start SIEM forwarder if configured
    _get_siem_forwarder()

# ---------------------------------------------------------------------------
# Helper: enrich evidence with optional trace / severity / metadata fields
# ---------------------------------------------------------------------------

def _enrich_evidence(
    evidence: Dict[str, Any],
    severity: Optional[str],
    trace_id: Optional[str],
    span_id: Optional[str],
    metadata: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    enriched = dict(evidence)
    if severity:
        enriched["severity"] = severity
    if trace_id:
        enriched["trace_id"] = trace_id
    if span_id:
        enriched["span_id"] = span_id
    if metadata:
        enriched["metadata"] = metadata
    return enriched

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# 1. POST /events -- ingest a single event ----------------------------------

@app.post(
    "/events",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new event",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:write")), Depends(_rate_limit)],
)
async def create_event(body: EventCreateRequest, request: Request):
    """Record a single audit event into the Vestigia ledger."""
    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None

    contract_event = body.evidence.get("contract_event") if isinstance(body.evidence, dict) else None
    if MLRT_ENFORCE_CONTRACT and contract_event is not None:
        err = _validate_contract_event(contract_event)
        if err:
            raise HTTPException(status_code=422, detail=err)
        if MLRT_REQUIRE_CORRELATION:
            corr_err = _require_correlation_fields(contract_event)
            if corr_err:
                raise HTTPException(status_code=422, detail=corr_err)
    if isinstance(contract_event, dict):
        body.evidence["contract_event"] = _backfill_contract_correlation(contract_event, body.actor_id)

    enriched = _enrich_evidence(
        body.evidence, body.severity, body.trace_id, body.span_id, body.metadata
    )
    # Phase 5 anomaly scoring
    anomaly_actor = f"{tenant_id}:{body.actor_id}" if tenant_id else body.actor_id
    score = _anomaly_detector.score_event(anomaly_actor, {
        "action_type": body.action_type,
        "status": body.status,
        "evidence": enriched
    })
    if _metric_anomaly_scored:
        _metric_anomaly_scored.inc()
    enriched["anomaly_risk"] = score["risk_score"]
    enriched["anomaly_signals"] = score["signals"]
    _anomaly_detector.update_baseline(anomaly_actor, {
        "action_type": body.action_type,
        "status": body.status,
        "evidence": enriched
    })

    try:
        event = ledger.append_event(
            actor_id=body.actor_id,
            action_type=body.action_type,
            status=body.status,
            evidence=enriched,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        logger.exception("Failed to append event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ledger write failed: {exc}",
        )

    # Record risk history for forecasting
    try:
        _risk_history.append(anomaly_actor, event.event_id, score["risk_score"], score["signals"])
        if tenant_id:
            _tenant_store.record_usage(tenant_id, events=1)
    except Exception:
        logger.exception("Failed to record risk history")

    # Playbook automation
    try:
        playbook_event = {
            "event_id": event.event_id,
            "actor_id": body.actor_id,
            "action_type": body.action_type,
            "status": body.status,
            "evidence": enriched,
        }
        matches = _playbook_engine.match(playbook_event, score["risk_score"])
        for pb in matches:
            _playbook_engine.execute(pb, playbook_event, score["risk_score"])
            if _metric_playbooks:
                _metric_playbooks.inc()
    except Exception:
        logger.exception("Failed to execute playbook(s)")

    # Auto-alert on high risk
    if score["risk_score"] >= 80:
        try:
            alert_event = ledger.append_event(
                actor_id="anomaly_detector",
                action_type="ANOMALY_ALERT",
                status="WARNING",
                evidence={
                    "summary": "High-risk anomaly detected",
                    "actor_id": body.actor_id,
                    "risk_score": score["risk_score"],
                    "signals": score["signals"],
                },
                tenant_id=tenant_id,
            )
            if _metric_anomaly_alerts:
                _metric_anomaly_alerts.inc()
            forwarder = _get_siem_forwarder()
            if forwarder:
                forwarder.forward_event({
                    "event_id": alert_event.event_id,
                    "actor_id": body.actor_id,
                    "action_type": body.action_type,
                    "status": body.status,
                    "risk_score": score["risk_score"],
                    "signals": score["signals"],
                    "timestamp": alert_event.timestamp,
                })
        except Exception:
            logger.exception("Failed to record anomaly alert")

    return EventResponse(
        event_id=event.event_id,
        integrity_hash=event.integrity_hash,
        timestamp=event.timestamp,
        status="recorded",
    )


# 2. GET /events -- query events --------------------------------------------

@app.get(
    "/events",
    response_model=EventListResponse,
    summary="Query events",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def list_events(
    request: Request,
    actor_id: Optional[str] = Query(None, description="Filter by actor ID"),
    action_type: Optional[str] = Query(None, description="Filter by action type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity in evidence"),
    start_date: Optional[str] = Query(None, description="ISO-8601 start date"),
    end_date: Optional[str] = Query(None, description="ISO-8601 end date"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """Query the ledger with optional filters and pagination."""
    ledger = _get_ledger()

    # Parse date filters
    parsed_start = None
    parsed_end = None
    try:
        if start_date:
            parsed_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        if end_date:
            parsed_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid date format: {exc}",
        )

    # query_events already returns newest-first and respects limit
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    events = ledger.query_events(
        tenant_id=tenant_id,
        actor_id=actor_id,
        action_type=action_type,
        status=status,
        start_date=parsed_start,
        end_date=parsed_end,
        limit=limit + offset,  # fetch enough to support offset
    )

    # Post-filter by severity (stored inside evidence dict)
    if severity:
        events = [
            e for e in events
            if (isinstance(e.evidence, dict) and e.evidence.get("severity") == severity)
        ]

    total = len(events)
    page = events[offset: offset + limit]

    _log_access(
        request=request,
        query_text=f"GET /events actor_id={actor_id} action_type={action_type} status={status}",
        rows_accessed=total,
    )

    return EventListResponse(
        events=[e.to_dict() for e in page],
        total=total,
        limit=limit,
        offset=offset,
    )


# 3. GET /events/{event_id} -- get single event -----------------------------

@app.get(
    "/events/{event_id}",
    response_model=EventDetailResponse,
    summary="Get a single event by ID",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def get_event(event_id: str, request: Request):
    """Retrieve a single event from the ledger by its event_id."""
    ledger = _get_ledger()

    # Linear scan -- acceptable for JSON-file backend; swap for indexed
    # lookup when PostgreSQL backend is active.
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    trail = ledger._load_ledger()
    for entry in trail:
        if entry.get("event_id") == event_id:
            if tenant_id and entry.get("tenant_id") != tenant_id:
                break
            _log_access(
                request=request,
                query_text=f"GET /events/{event_id}",
                rows_accessed=1,
            )
            return EventDetailResponse(
                timestamp=entry["timestamp"],
                actor_id=entry["actor_id"],
                action_type=entry["action_type"],
                status=entry["status"],
                evidence=entry["evidence"],
                integrity_hash=entry["integrity_hash"],
                event_id=entry["event_id"],
                previous_hash=entry.get("previous_hash", "GENESIS"),
                severity=entry.get("evidence", {}).get("severity") if isinstance(entry.get("evidence"), dict) else None,
                trace_id=entry.get("evidence", {}).get("trace_id") if isinstance(entry.get("evidence"), dict) else None,
                span_id=entry.get("evidence", {}).get("span_id") if isinstance(entry.get("evidence"), dict) else None,
                metadata=entry.get("evidence", {}).get("metadata") if isinstance(entry.get("evidence"), dict) else None,
            )

    _log_access(
        request=request,
        query_text=f"GET /events/{event_id}",
        rows_accessed=0,
    )
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Event '{event_id}' not found",
    )


# 3b. GET /events/export -- export events (CSV) ----------------------------

@app.get(
    "/events/export",
    response_class=PlainTextResponse,
    summary="Export events as CSV",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def export_events(
    request: Request,
    limit: int = Query(1000, ge=1, le=100000),
    approver_1: Optional[str] = Header(None, alias="X-Approver-1"),
    approver_2: Optional[str] = Header(None, alias="X-Approver-2"),
):
    if limit > 10000:
        if not approver_1 or not approver_2 or approver_1 == approver_2:
            raise HTTPException(status_code=403, detail="Two-person approval required for large exports")

    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    events = ledger.query_events(tenant_id=tenant_id, limit=limit)
    rows = [e.to_dict() for e in events]

    # log access
    _log_access(
        request=request,
        query_text=f"GET /events/export limit={limit}",
        rows_accessed=len(rows),
    )

    # CSV export
    if not rows:
        return ""
    headers = list(rows[0].keys())
    lines = [",".join(headers)]
    for row in rows:
        lines.append(",".join(str(row.get(h, "")).replace(",", " ") for h in headers))
    return "\n".join(lines)


# 4. POST /events/batch -- batch ingest -------------------------------------

@app.post(
    "/events/batch",
    response_model=BatchEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Batch ingest events",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:write")), Depends(_rate_limit)],
)
async def batch_create_events(body: BatchEventRequest, request: Request):
    """Record multiple events in a single request."""
    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    recorded: List[EventResponse] = []
    failed = 0

    for item in body.events:
        try:
            contract_event = item.evidence.get("contract_event") if isinstance(item.evidence, dict) else None
            if MLRT_ENFORCE_CONTRACT and contract_event is not None:
                err = _validate_contract_event(contract_event)
                if err:
                    failed += 1
                    continue
                if MLRT_REQUIRE_CORRELATION:
                    corr_err = _require_correlation_fields(contract_event)
                    if corr_err:
                        failed += 1
                        continue
            if isinstance(contract_event, dict):
                item.evidence["contract_event"] = _backfill_contract_correlation(contract_event, item.actor_id)
            enriched = _enrich_evidence(
                item.evidence, item.severity, item.trace_id, item.span_id, item.metadata
            )
            event = ledger.append_event(
                actor_id=item.actor_id,
                action_type=item.action_type,
                status=item.status,
                evidence=enriched,
                tenant_id=tenant_id,
            )
            recorded.append(
                EventResponse(
                    event_id=event.event_id,
                    integrity_hash=event.integrity_hash,
                    timestamp=event.timestamp,
                    status="recorded",
                )
            )
        except Exception:
            logger.exception("Failed to record batch item for actor=%s", item.actor_id)
            failed += 1

    if tenant_id and recorded:
        _tenant_store.record_usage(tenant_id, events=len(recorded))

    return BatchEventResponse(
        recorded=len(recorded),
        failed=failed,
        events=recorded,
    )


# 5. GET /health -- health check --------------------------------------------

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
)
async def health_check():
    """Return service health including ledger validity."""
    ledger = _get_ledger()
    stats = ledger.get_statistics()
    full_check = os.getenv("VESTIGIA_HEALTH_FULL", "false").lower() in ("1", "true", "yes")
    global _last_integrity_check_ts, _last_integrity_ok
    if full_check:
        is_valid, _ = ledger.verify_integrity()
        _last_integrity_ok = bool(is_valid)
        _last_integrity_check_ts = time.monotonic()
    else:
        is_valid = _last_integrity_ok

    return HealthResponse(
        status="healthy",
        version=API_VERSION,
        uptime_seconds=round(time.monotonic() - _startup_time, 2),
        total_events=stats.get("total_events", 0),
        ledger_valid=is_valid,
    )


@app.get(
    "/status",
    summary="Infrastructure status page data",
)
async def status_page():
    health = collect_health(LEDGER_PATH, DB_DSN, REDIS_URL)
    overall = "ok"
    for comp in health["components"]:
        if comp["status"] == "fail":
            overall = "fail"
            break
        if comp["status"] == "warning" and overall != "fail":
            overall = "warning"
    return {
        "status": overall,
        "version": API_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        **health,
    }


@app.get(
    "/continuity/check",
    summary="Check evidence continuity for contract events within a time window",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def continuity_check(
    request: Request,
    minutes: int = Query(60, ge=1, le=1440),
):
    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    cutoff = datetime.now(UTC) - timedelta(minutes=minutes)
    entries = [e.to_dict() for e in ledger.query_events(tenant_id=tenant_id, limit=50000)]

    checked = 0
    correlated = 0
    missing = 0
    for e in entries:
        try:
            ts = datetime.fromisoformat(str(e.get("timestamp", "")).replace("Z", "+00:00"))
        except Exception:
            continue
        if ts < cutoff:
            continue
        evidence = e.get("evidence", {})
        if not isinstance(evidence, dict):
            continue
        ce = evidence.get("contract_event")
        if not isinstance(ce, dict):
            continue
        checked += 1
        actor = ce.get("actor") or {}
        req = ce.get("request") or {}
        if actor.get("agent_id") and req.get("session_id") and req.get("trace_id"):
            correlated += 1
        else:
            missing += 1

    continuity_pct = round((correlated / checked) * 100.0, 2) if checked else 100.0
    return {
        "window_minutes": minutes,
        "checked_contract_events": checked,
        "correlated_events": correlated,
        "missing_correlation": missing,
        "continuity_pct": continuity_pct,
        "status": "pass" if continuity_pct >= 99.0 else "fail",
    }


@app.post(
    "/verify/attestation",
    summary="Verify Ed25519 attestation payload/signature pair",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def verify_attestation(body: EvidenceVerifyRequest):
    hash_value = hashlib.sha256(_canonical_bytes(body.payload)).hexdigest()
    if body.expected_hash and body.expected_hash != hash_value:
        return {"valid": False, "signature_valid": False, "hash_match": False, "hash": hash_value}
    signature_valid = _verify_ed25519(body.public_key, body.payload, body.signature)
    return {
        "valid": bool(signature_valid),
        "signature_valid": bool(signature_valid),
        "hash_match": True,
        "hash": hash_value,
    }


# 6. GET /integrity -- verify ledger integrity ------------------------------

@app.get(
    "/integrity",
    response_model=IntegrityResponse,
    summary="Verify ledger integrity",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def verify_integrity(request: Request):
    """Run a full forensic validation of the ledger and return the report."""
    ledger = _get_ledger()

    validator = VestigiaValidator(ledger_path=str(ledger.ledger_path))
    report = validator.validate_full()

    issues_serialised = [
        {
            "severity": issue.severity.value,
            "entry_index": issue.entry_index,
            "type": issue.issue_type,
            "description": issue.description,
            "evidence": issue.evidence,
        }
        for issue in report.issues
    ]

    return IntegrityResponse(
        is_valid=report.is_valid,
        total_entries=report.total_entries,
        issues=issues_serialised,
    )


# 7. GET /statistics -- ledger statistics -----------------------------------

@app.get(
    "/statistics",
    summary="Get ledger statistics",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def get_statistics(request: Request):
    """Return aggregate statistics about the ledger contents."""
    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    stats = ledger.get_statistics(tenant_id=tenant_id)
    _log_access(
        request=request,
        query_text="GET /statistics",
        rows_accessed=stats.get("total_events", 0),
    )
    return stats


# 8. POST /webhooks/siem -- SIEM enrichment webhook -------------------------

@app.post(
    "/webhooks/siem",
    response_model=SIEMWebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="SIEM alert webhook",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:write")), Depends(_rate_limit)],
)
async def siem_webhook(body: SIEMWebhookRequest, request: Request):
    """Receive a SIEM alert, enrich it, and record it in the ledger."""
    ledger = _get_ledger()

    # Count how many of the referenced events actually exist in the ledger
    matched_count = 0
    if body.affected_events:
        trail = ledger._load_ledger()
        existing_ids = {e.get("event_id") for e in trail}
        matched_count = sum(1 for eid in body.affected_events if eid in existing_ids)

    enriched_event_id = f"siem_{uuid.uuid4().hex[:12]}"

    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    try:
        ledger.append_event(
            actor_id=f"siem:{body.source}",
            action_type="SIEM_ALERT",
            status=body.severity.upper() if body.severity else "WARNING",
            evidence={
                "summary": body.description,
                "siem_source": body.source,
                "alert_id": body.alert_id,
                "severity": body.severity,
                "affected_events": body.affected_events or [],
                "matched_events": matched_count,
            },
            event_id=enriched_event_id,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        logger.exception("Failed to record SIEM alert")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ledger write failed: {exc}",
        )

    return SIEMWebhookResponse(
        status="recorded",
        enriched_event_id=enriched_event_id,
        matched_events=matched_count,
    )


# 9. GET /anchors -- list blockchain anchors -------------------------------

@app.get(
    "/anchors",
    summary="List blockchain anchors",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def list_anchors(request: Request):
    anchor = _get_blockchain_anchor()
    data = anchor.list_anchors()
    _log_access(request, "GET /anchors", len(data.get("anchors", [])))
    return data


# 10. GET /anchors/{anchor_id} -- verify anchor ----------------------------

@app.get(
    "/anchors/{anchor_id}",
    summary="Verify blockchain anchor",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def verify_anchor(anchor_id: str, request: Request):
    anchor = _get_blockchain_anchor()
    record = anchor.verify_anchor(anchor_id)
    _log_access(request, f"GET /anchors/{anchor_id}", 1)
    if not record:
        raise HTTPException(status_code=404, detail="Anchor not found")
    return record


# 12. POST /anomalies/score -- score without storing -----------------------

@app.post(
    "/anomalies/score",
    response_model=AnomalyScoreResponse,
    summary="Score an event for anomalies (dry-run)",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def anomaly_score(body: AnomalyScoreRequest, request: Request):
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    actor_key = f"{tenant_id}:{body.actor_id}" if tenant_id else body.actor_id
    score = _anomaly_detector.score_event(actor_key, {
        "action_type": body.action_type,
        "status": body.status,
        "evidence": body.evidence
    })
    return AnomalyScoreResponse(risk_score=score["risk_score"], signals=score["signals"])


@app.post(
    "/anomalies/feedback",
    summary="Provide feedback for anomaly (benign)",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("anomalies:feedback")), Depends(_rate_limit)],
)
async def anomaly_feedback(body: AnomalyFeedbackRequest, request: Request):
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    actor_key = f"{tenant_id}:{body.actor_id}" if tenant_id else body.actor_id
    _anomaly_detector.record_feedback(body.event_id, actor_key, label="benign", note=body.note or "")
    return {"status": "recorded"}


@app.post(
    "/nl/query",
    response_model=NLQueryResponse,
    summary="Execute a natural language query",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("nl:query")), Depends(_rate_limit)],
)
async def nl_query(body: NLQueryRequest, request: Request):
    parsed = _nl_query_engine.parse(body.query)
    ledger = _get_ledger()
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    events = ledger.query_events(
        tenant_id=tenant_id,
        actor_id=parsed["filters"].get("actor_id"),
        action_type=parsed["filters"].get("action_type"),
        status=parsed["filters"].get("status"),
        start_date=parsed["filters"].get("start_date"),
        end_date=parsed["filters"].get("end_date"),
        limit=body.limit,
    )
    results = [e.__dict__ for e in events]
    results = _nl_query_engine.apply(results, parsed["post_filters"])
    if _metric_nl_queries:
        _metric_nl_queries.inc()
    return NLQueryResponse(
        filters=parsed["filters"],
        post_filters=parsed["post_filters"],
        results=results,
        total=len(results),
    )


@app.get(
    "/playbooks",
    summary="List available playbooks",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def list_playbooks():
    return {"playbooks": _playbook_engine.store.load()}


@app.post(
    "/playbooks/execute",
    response_model=PlaybookExecuteResponse,
    summary="Execute a playbook by name",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("playbooks:execute")), Depends(_rate_limit)],
)
async def execute_playbook(body: PlaybookExecuteRequest):
    playbooks = _playbook_engine.store.load()
    selected = next((p for p in playbooks if p.get("name") == body.name), None)
    if not selected:
        raise HTTPException(status_code=404, detail="Playbook not found")
    event = {
        "event_id": None,
        "actor_id": body.actor_id,
        "action_type": body.action_type,
        "status": body.status,
        "evidence": body.evidence or {},
    }
    payload = _playbook_engine.execute(selected, event, body.risk_score)
    if _metric_playbooks:
        _metric_playbooks.inc()
    return PlaybookExecuteResponse(
        playbook_name=payload["playbook_name"],
        executed_at=payload["executed_at"],
        details=payload["details"],
    )


@app.get(
    "/risk/forecast",
    response_model=RiskForecastResponse,
    summary="Forecast risk for an actor",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("risk:forecast")), Depends(_rate_limit)],
)
async def risk_forecast(actor_id: str, horizon_hours: int = 24, request: Request = None):
    tenant_id = getattr(request.state, "tenant_id", None) if MULTI_TENANT else None
    actor_key = f"{tenant_id}:{actor_id}" if tenant_id else actor_id
    forecast = _risk_forecaster.forecast(actor_key, horizon_hours=horizon_hours)
    if _metric_risk_forecasts:
        _metric_risk_forecasts.inc()
    return RiskForecastResponse(
        actor_id=actor_id,
        forecast_horizon=forecast["forecast_horizon"],
        predicted_risk=forecast["predicted_risk"],
        confidence_interval=list(forecast["confidence_interval"]),
        recommendation=forecast["recommendation"],
    )


@app.post(
    "/tenants",
    response_model=TenantCreateResponse,
    summary="Create a new tenant (platform admin only)",
    dependencies=[Depends(_require_platform_admin), Depends(_rate_limit)],
)
async def create_tenant(body: TenantCreateRequest):
    tenant = _tenant_store.create_tenant(body.name, plan=body.plan)
    admin = _tenant_store.create_user(tenant["tenant_id"], email=body.admin_email, role="admin")
    api_key = _tenant_store.create_api_key(tenant["tenant_id"], user_id=admin["user_id"], label="admin")
    return TenantCreateResponse(
        tenant_id=tenant["tenant_id"],
        name=tenant["name"],
        plan=tenant["plan"],
        admin_user_id=admin["user_id"],
        api_key=api_key["api_key"],
    )


@app.post(
    "/tenants/{tenant_id}/users",
    summary="Create a user within a tenant",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("tenant:manage")), Depends(_rate_limit)],
)
async def create_tenant_user(tenant_id: str, body: TenantUserCreateRequest, request: Request):
    _require_same_tenant(request, tenant_id)
    if body.role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail="Unsupported role")
    limits = _tenant_store.get_plan_limits(tenant_id)
    if limits.get("users") is not None:
        data = _tenant_store._load()
        current_users = len([u for u in data.get("users", {}).values() if u.get("tenant_id") == tenant_id])
        if current_users + 1 > limits["users"]:
            raise HTTPException(status_code=403, detail="Plan limit exceeded: users")
    user = _tenant_store.create_user(tenant_id, email=body.email, role=body.role)
    return {"status": "created", "user": user}


@app.post(
    "/tenants/{tenant_id}/apikeys",
    response_model=ApiKeyCreateResponse,
    summary="Create an API key for a tenant user",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("apikeys:manage")), Depends(_rate_limit)],
)
async def create_api_key(tenant_id: str, body: ApiKeyCreateRequest, request: Request):
    _require_same_tenant(request, tenant_id)
    api_key = _tenant_store.create_api_key(tenant_id, user_id=body.user_id, label=body.label)
    return ApiKeyCreateResponse(**api_key)


@app.get(
    "/metrics",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("metrics:read"))],
)
def metrics():
    if not generate_latest:
        raise HTTPException(status_code=500, detail="prometheus_client not installed")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# 11. GET /witness/public_key -- HSM public key ----------------------------

@app.get(
    "/witness/public_key",
    summary="Get HSM public key for witness signatures",
    dependencies=[Depends(_require_api_key), Depends(_require_permission("events:read")), Depends(_rate_limit)],
)
async def witness_public_key(request: Request):
    ledger = _get_ledger()
    if not getattr(ledger, "witness", None):
        raise HTTPException(status_code=404, detail="Witness not enabled")
    pub = ledger.witness.get_public_key()
    if not pub:
        raise HTTPException(status_code=404, detail="HSM not configured")
    _log_access(request, "GET /witness/public_key", 1)
    return {"public_key_pem": pub}


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    certfile = os.getenv("VESTIGIA_TLS_CERTFILE") or os.getenv("TLS_CERTFILE")
    keyfile = os.getenv("VESTIGIA_TLS_KEYFILE") or os.getenv("TLS_KEYFILE")
    ssl_kwargs = {}
    if certfile and keyfile:
        ssl_kwargs = {"ssl_certfile": certfile, "ssl_keyfile": keyfile}

    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=int(os.getenv("VESTIGIA_PORT", "8002")),
        reload=os.getenv("VESTIGIA_MODE", "production") == "development",
        log_level="info",
        **ssl_kwargs,
    )

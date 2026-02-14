#!/usr/bin/env python3
"""
VerityFlux Enterprise - FastAPI REST API Layer
Comprehensive REST API exposing all platform functionality

Features:
- Authentication (JWT, API Keys)
- Vulnerability Database endpoints
- Security Scanner endpoints
- SOC Command Center endpoints
- HITL approval endpoints
- Integration management
- Webhook receivers
- WebSocket real-time updates
"""

import os
import json
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from pathlib import Path as FSPath

# FastAPI
from fastapi import (
    FastAPI, HTTPException, Depends, Security, Query, Path, Body,
    BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Response
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from urllib import request as urllib_request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, EmailStr

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verityflux.api")

# Core scanner (v2)
from core.scanner import VerityFluxScanner
from core.types import ScanConfig, RiskLevel
from cognitive_firewall.firewall import reload_all_policies

# In-memory scan state (demo-safe; replace with DB/queue in production)
SCAN_STORE: Dict[str, Dict[str, Any]] = {}
# In-memory SOC agent inventory (demo-safe; replace with DB in production)
AGENT_STORE: Dict[str, Dict[str, Any]] = {}

# Policy helpers
BASE_DIR = FSPath(__file__).resolve().parents[2]


def _policy_path() -> FSPath:
    env_path = os.getenv("VERITYFLUX_POLICY_PATH")
    if env_path:
        return FSPath(env_path)
    return BASE_DIR / "config" / "policy.json"


def _agent_store_path() -> FSPath:
    env_path = os.getenv("VERITYFLUX_AGENT_STORE_PATH")
    if env_path:
        return FSPath(env_path)
    return BASE_DIR / "data" / "soc_agents.json"


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _load_agent_store() -> None:
    path = _agent_store_path()
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        agents = payload.get("agents", {})
        if not isinstance(agents, dict):
            return
        AGENT_STORE.clear()
        for aid, row in agents.items():
            if not isinstance(row, dict):
                continue
            record = dict(row)
            for dt_key in ("last_seen_at", "created_at", "updated_at"):
                val = record.get(dt_key)
                if isinstance(val, str):
                    try:
                        record[dt_key] = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except Exception:
                        record[dt_key] = None
            AGENT_STORE[str(aid)] = record
    except Exception as exc:
        logger.warning("Failed to load agent store: %s", exc)


def _save_agent_store() -> None:
    path = _agent_store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if BASE_DIR not in path.resolve().parents:
            raise ValueError("Agent store path must be within repo")
        payload = {"agents": AGENT_STORE}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=_json_default)
    except Exception as exc:
        logger.warning("Failed to save agent store: %s", exc)


def _load_policy() -> Dict[str, Any]:
    path = _policy_path()
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to load policy from %s: %s", path, exc)
        return {}


def _write_policy(policy: Dict[str, Any]) -> None:
    path = _policy_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Only allow writes within repo
        if BASE_DIR not in path.resolve().parents:
            raise ValueError("Policy path must be within repo")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2, sort_keys=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to write policy: {exc}")

# ---------------------------------------------------------------------------
# Integration hooks (opt-in)
# ---------------------------------------------------------------------------

def _integration_enabled() -> bool:
    return os.getenv("MLRT_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes")


def _shared_audit_log_path() -> FSPath:
    raw = os.getenv("SUITE_AUDIT_LOG")
    if raw:
        p = FSPath(raw)
        if not p.is_absolute():
            p = BASE_DIR / raw
        return p
    return BASE_DIR / "shared_state" / "shared_audit.log"


def _validate_contract_event(event: dict) -> bool:
    required = ["timestamp", "source", "event_type", "outcome"]
    for key in required:
        if key not in event:
            return False
    if not isinstance(event.get("outcome"), dict) or "status" not in event["outcome"]:
        return False
    return True


def _send_to_vestigia(event: dict) -> None:
    if not _integration_enabled():
        return
    if not _validate_contract_event(event):
        return
    ingest_url = os.getenv("MLRT_VESTIGIA_INGEST_URL", "http://localhost:8002/events")
    api_key = os.getenv("MLRT_VESTIGIA_API_KEY") or os.getenv("VESTIGIA_API_KEY", "")

    payload = {
        "actor_id": event.get("actor", {}).get("agent_id", "unknown"),
        "action_type": event.get("event_type", "unknown"),
        "status": event.get("outcome", {}).get("status", "unknown"),
        "evidence": {"contract_event": event},
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    delivered = False
    try:
        req = urllib_request.Request(
            ingest_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=2) as _:
            delivered = True
    except Exception:
        delivered = False

    # Fallback: always keep suite-level shared audit continuity if API ingest fails.
    if not delivered:
        try:
            shared = _shared_audit_log_path()
            shared.parent.mkdir(parents=True, exist_ok=True)
            ts = event.get("timestamp") or datetime.now(UTC).isoformat()
            actor = str(event.get("actor", {}).get("agent_id") or "VERITYFLUX")
            action = str(event.get("event_type") or "UNKNOWN").upper()
            out_status = str(event.get("outcome", {}).get("status") or "INFO").upper()
            evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
            summary = evidence.get("summary") or f"{action} emitted by VerityFlux"
            with open(shared, "a", encoding="utf-8") as f:
                f.write(f"{ts} | {actor} | {action} | status:{out_status} | {summary}\n")
        except Exception:
            return


def _emit_integration_event(
    *,
    event_type: str,
    agent_id: str,
    status: str,
    evidence: Optional[dict] = None,
    reason: Optional[str] = None,
) -> None:
    if not _integration_enabled():
        return
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "verityflux",
        "event_type": event_type,
        "actor": {"agent_id": agent_id},
        "outcome": {"status": status, "reason": reason},
        "evidence": evidence or {},
    }
    _send_to_vestigia(event)


def _risk_level_from_score(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _finding_risk_score(threat: Any, overall_risk_score: float) -> float:
    severity = threat.risk_level.value if isinstance(threat.risk_level, RiskLevel) else str(threat.risk_level)
    base = {
        "critical": 92.0,
        "high": 76.0,
        "medium": 58.0,
        "low": 35.0,
        "info": 12.0,
    }.get(str(severity).lower(), 50.0)
    confidence = getattr(threat, "confidence", None)
    try:
        conf = float(confidence)
        if conf < 0:
            conf = 0.0
        if conf > 100:
            conf = 100.0
    except Exception:
        conf = 50.0
    score = (base * 0.7) + (conf * 0.3)
    # Keep finding-level score coherent with scan-level context while preserving severity differences.
    if overall_risk_score and score < (overall_risk_score * 0.35):
        score = overall_risk_score * 0.35
    return round(min(100.0, max(0.0, score)), 2)


def _require_admin(user: Dict[str, Any]) -> None:
    role = user.get("role")
    perms = user.get("permissions", [])
    if role not in ("admin", "super_admin") and "admin" not in perms:
        raise HTTPException(status_code=403, detail="Admin permission required")


def _build_target_dict(target: "ScanTargetRequest") -> Dict[str, Any]:
    return {
        "provider": target.target_type,
        "model": target.model_name,
        "base_url": target.endpoint_url,
        "is_agent": target.config.get("is_agent", False),
        "has_tools": target.config.get("has_tools", False),
        "has_memory": target.config.get("has_memory", False),
        "has_rag": target.config.get("has_rag", False),
        "extra": target.config,
    }


def _run_scan_job(scan_id: str, target: "ScanTargetRequest", config: Optional["ScanConfigRequest"], user: Dict):
    started_at = SCAN_STORE[scan_id]["started_at"]
    SCAN_STORE[scan_id]["status"] = "running"
    try:
        scan_config = ScanConfig(
            scan_llm_threats=True,
            scan_agentic_threats=True,
            max_test_samples=5 if (config and config.profile == "quick") else 10,
            timeout_seconds=30,
            verbose=False,
        )
        scanner = VerityFluxScanner(application_name=target.name, config=scan_config)
        report = scanner.scan_all(_build_target_dict(target))

        findings = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for threat in report.llm_threats + report.agentic_threats:
            if not threat.detected:
                continue
            severity = threat.risk_level.value if isinstance(threat.risk_level, RiskLevel) else str(threat.risk_level)
            summary[severity] = summary.get(severity, 0) + 1
            findings.append(ScanFindingResponse(
                id=f"{scan_id}:{threat.threat_type}",
                vuln_id=threat.threat_type,
                title=threat.threat_type,
                severity=severity,
                status="confirmed",
                target_name=target.name,
                component="agentic" if threat.threat_type.startswith("aai") else "llm",
                description=threat.description,
                recommendation="; ".join(threat.recommendations) if threat.recommendations else "",
                risk_score=_finding_risk_score(threat, report.overall_risk_score),
                cvss_score=None,
                test_payload=threat.evidence.get("payload") if isinstance(threat.evidence, dict) else None,
                response_snippet=threat.evidence.get("response") if isinstance(threat.evidence, dict) else None,
            ))

        completed_at = datetime.utcnow()
        result = ScanResultResponse(
            scan_id=scan_id,
            status="completed",
            target_name=target.name,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=report.scan_duration_seconds,
            total_tests=len(report.llm_threats) + len(report.agentic_threats),
            passed_tests=(len(report.llm_threats) + len(report.agentic_threats)) - report.total_threats,
            failed_tests=report.total_threats,
            overall_risk_score=report.overall_risk_score,
            risk_level=_risk_level_from_score(report.overall_risk_score),
            findings_summary=summary,
            findings=findings,
        )

        SCAN_STORE[scan_id].update({
            "status": "completed",
            "completed_at": completed_at,
            "result": result,
        })

        _emit_integration_event(
            event_type="scan_completed",
            agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
            status="success",
            evidence={
                "scan_id": scan_id,
                "target": target.name,
                "risk_score": report.overall_risk_score,
                "findings_summary": summary,
            },
        )
    except Exception as exc:
        SCAN_STORE[scan_id].update({
            "status": "failed",
            "error": str(exc),
            "completed_at": datetime.utcnow(),
        })
        _emit_integration_event(
            event_type="scan_failed",
            agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
            status="error",
            reason=str(exc),
            evidence={"scan_id": scan_id, "target": target.name},
        )


# =============================================================================
# PYDANTIC MODELS (Request/Response Schemas)
# =============================================================================

# -----------------------------------------------------------------------------
# Auth Models
# -----------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    organization_id: str
    role: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class APIKeyCreateRequest(BaseModel):
    name: str
    permissions: List[str] = Field(default_factory=list)
    expires_in_days: Optional[int] = 365


class APIKeyResponse(BaseModel):
    key_id: str
    key_prefix: str
    api_key: Optional[str] = None  # Only returned on creation
    name: str
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime]


# -----------------------------------------------------------------------------
# Vulnerability Models
# -----------------------------------------------------------------------------

class VulnerabilityResponse(BaseModel):
    vuln_id: str
    source: str
    category: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    recommendation: Optional[str]
    references: List[str]
    tags: List[str]


class VulnerabilitySearchRequest(BaseModel):
    query: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    min_cvss: Optional[float] = None
    tags: Optional[List[str]] = None
    limit: int = Field(default=50, le=200)
    offset: int = 0


class VulnerabilitySyncResponse(BaseModel):
    source: str
    success: bool
    total_fetched: int
    new_records: int
    updated_records: int
    errors: List[str]
    duration_seconds: float


# -----------------------------------------------------------------------------
# Scanner Models
# -----------------------------------------------------------------------------

class ScanTargetRequest(BaseModel):
    target_type: str  # openai, anthropic, ollama, custom_api
    name: str
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)


class ScanConfigRequest(BaseModel):
    profile: str = "standard"  # quick, standard, deep, compliance
    vuln_ids: Optional[List[str]] = None
    exclude_vuln_ids: List[str] = Field(default_factory=list)
    max_requests_per_vuln: int = 5
    concurrent_tests: int = 3
    include_evidence: bool = True


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str
    target_name: str
    profile: str
    started_at: datetime
    estimated_duration_minutes: int


class ScanProgressResponse(BaseModel):
    scan_id: str
    status: str
    progress_percent: float
    completed_tests: int
    total_tests: int
    current_vuln: str
    findings_count: int
    elapsed_seconds: float
    estimated_remaining_seconds: Optional[float]


class ScanFindingResponse(BaseModel):
    id: str
    vuln_id: str
    title: str
    severity: str
    status: str
    target_name: str
    component: str
    description: str
    recommendation: str
    risk_score: float
    cvss_score: Optional[float]
    test_payload: Optional[str]
    response_snippet: Optional[str]


class ScanResultResponse(BaseModel):
    scan_id: str
    status: str
    target_name: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: float
    total_tests: int
    passed_tests: int
    failed_tests: int
    overall_risk_score: float
    risk_level: str
    findings_summary: Dict[str, int]
    findings: List[ScanFindingResponse]


# -----------------------------------------------------------------------------
# Policy Models
# -----------------------------------------------------------------------------

class PolicyResponse(BaseModel):
    policy: Dict[str, Any]
    path: str
    note: str


class PolicyUpdateRequest(BaseModel):
    policy: Dict[str, Any]


# -----------------------------------------------------------------------------
# SOC Models
# -----------------------------------------------------------------------------

class SecurityEventRequest(BaseModel):
    agent_id: str
    agent_name: str
    event_type: str
    severity: str = "medium"
    tool_name: Optional[str] = None
    action_parameters: Dict[str, Any] = Field(default_factory=dict)
    decision: str = "allow"
    risk_score: float = 0.0
    violations: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    user_id: Optional[str] = None


class AlertResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str
    agent_id: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    incident_id: Optional[str]


class IncidentCreateRequest(BaseModel):
    title: str
    description: str
    incident_type: str
    priority: str = "p3_medium"
    affected_agents: List[str] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)


class IncidentResponse(BaseModel):
    id: str
    number: str
    title: str
    description: str
    incident_type: str
    priority: str
    status: str
    created_at: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    assigned_to: Optional[str]
    sla_response_breached: bool
    sla_resolution_breached: bool
    affected_agents: List[str]
    impact_score: int


class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    comment: Optional[str] = None
    root_cause: Optional[str] = None
    resolution_summary: Optional[str] = None


class AgentRegisterRequest(BaseModel):
    name: str
    agent_type: str
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    tools: List[str] = Field(default_factory=list)
    environment: str = "production"


class AgentResponse(BaseModel):
    id: str
    name: str
    agent_type: str
    status: str
    model_provider: Optional[str]
    model_name: Optional[str]
    tools: List[str]
    total_requests: int
    blocked_requests: int
    health_score: float
    last_seen_at: Optional[datetime]


def _agent_to_response(agent: Dict[str, Any]) -> AgentResponse:
    return AgentResponse(
        id=str(agent.get("id")),
        name=str(agent.get("name")),
        agent_type=str(agent.get("agent_type")),
        status=str(agent.get("status", "healthy")),
        model_provider=agent.get("model_provider"),
        model_name=agent.get("model_name"),
        tools=list(agent.get("tools", []) or []),
        total_requests=int(agent.get("total_requests", 0) or 0),
        blocked_requests=int(agent.get("blocked_requests", 0) or 0),
        health_score=float(agent.get("health_score", 100.0) or 0.0),
        last_seen_at=agent.get("last_seen_at"),
    )


class SOCMetricsResponse(BaseModel):
    timestamp: datetime
    period: str
    incidents: Dict[str, Any]
    sla: Dict[str, Any]
    events: Dict[str, Any]
    alerts: Dict[str, Any]
    agents: Dict[str, Any]
    threat_level: str


# -----------------------------------------------------------------------------
# HITL Models
# -----------------------------------------------------------------------------

class ApprovalContextRequest(BaseModel):
    agent_id: str
    agent_name: str
    tool_name: str
    action_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float
    risk_factors: List[str] = Field(default_factory=list)
    violations: List[str] = Field(default_factory=list)
    original_goal: Optional[str] = None
    reasoning_chain: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    user_id: Optional[str] = None


class ApprovalRequestResponse(BaseModel):
    id: str
    status: str
    risk_level: str
    title: str
    description: str
    created_at: datetime
    expires_at: datetime
    time_remaining_seconds: float
    assigned_to: List[str]
    decision: Optional[str]
    decided_by: Optional[str]
    justification: Optional[str]


class ApprovalDecisionRequest(BaseModel):
    decision: str  # approve, deny, approve_always, deny_always, escalate
    justification: str = ""
    conditions: List[str] = Field(default_factory=list)


class ApprovalPolicyRequest(BaseModel):
    name: str
    description: Optional[str] = None
    tool_patterns: List[str] = Field(default_factory=list)
    action_types: List[str] = Field(default_factory=list)
    min_risk_score: float = 0.0
    approver_users: List[str] = Field(default_factory=list)
    escalation_chain: List[List[str]] = Field(default_factory=list)


class ApprovalStatsResponse(BaseModel):
    total_requests: int
    by_status: Dict[str, int]
    by_type: Dict[str, int]
    auto_approved: int
    auto_denied: int
    avg_decision_time_seconds: float


# -----------------------------------------------------------------------------
# Integration Models
# -----------------------------------------------------------------------------

class IntegrationConfigRequest(BaseModel):
    name: str
    integration_type: str  # slack, jira, pagerduty, email, webhook
    config: Dict[str, Any]
    enabled: bool = True


class IntegrationResponse(BaseModel):
    name: str
    integration_type: str
    enabled: bool
    status: str
    last_used_at: Optional[datetime]


class NotificationRequest(BaseModel):
    notification_type: str
    priority: str = "medium"
    title: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    integrations: Optional[List[str]] = None


class WebhookEventRequest(BaseModel):
    event_type: str
    payload: Dict[str, Any]
    signature: Optional[str] = None


# -----------------------------------------------------------------------------
# Common Models
# -----------------------------------------------------------------------------

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    limit: int
    offset: int
    has_more: bool


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class SuccessResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


# =============================================================================
# APPLICATION SETUP
# =============================================================================

# Global service instances (initialized on startup)
auth_service = None
vulndb_service = None
scanner_service = None
soc_service = None
hitl_service = None
integration_manager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown"""
    global auth_service, vulndb_service, scanner_service, soc_service, hitl_service, integration_manager
    
    logger.info("Starting VerityFlux API...")
    
    # Initialize services (lazy imports to avoid circular dependencies)
    try:
        # These would be real service initializations in production
        # For now, we'll create placeholder references
        logger.info("Initializing services...")
        
        # In production, these would be:
        # from ..auth.authentication import AuthenticationService
        # from ..vulndb.vulnerability_service import VulnerabilityDatabaseService
        # from ..scanner.security_scanner import SecurityScanner
        # from ..soc.soc_command_center import SOCCommandCenter
        # from ..hitl.hitl_service import HITLService
        # from ..integrations.integration_service import IntegrationManager
        
        # auth_service = AuthenticationService(...)
        # vulndb_service = VulnerabilityDatabaseService()
        # scanner_service = SecurityScanner(vulndb_service)
        # integration_manager = IntegrationManager()
        # soc_service = SOCCommandCenter(integration_manager)
        # hitl_service = HITLService(integration_manager=integration_manager)
        
        # await soc_service.start()
        # await hitl_service.start()
        _load_agent_store()
        
        logger.info("Services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
    
    yield
    
    # Shutdown
    _save_agent_store()
    logger.info("Shutting down VerityFlux API...")
    
    # if soc_service:
    #     await soc_service.stop()
    # if hitl_service:
    #     await hitl_service.stop()


# Create FastAPI app
app = FastAPI(
    title="VerityFlux Enterprise API",
    description="AI Agent Security Platform - REST API",
    version="3.5.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# AUTHENTICATION DEPENDENCIES
# =============================================================================

security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    api_key: str = Security(api_key_header),
) -> Dict[str, Any]:
    """
    Authenticate request via JWT token or API key
    Returns user context dict
    """
    # Try API key first
    if api_key:
        # Validate API key
        # user = await auth_service.authenticate_api_key(api_key)
        # For now, return mock user
        if api_key.startswith("vf_admin_"):
            return {
                "user_id": "api-admin",
                "organization_id": "org-123",
                "role": "admin",
                "permissions": ["read", "write", "admin"],
            }
        if api_key.startswith("vf_"):
            return {
                "user_id": "api-user",
                "organization_id": "org-123",
                "role": "api_user",
                "permissions": ["read", "write"],
            }
    
    # Try JWT token
    if credentials:
        token = credentials.credentials
        # Validate JWT
        # payload = await auth_service.validate_token(token)
        # For now, return mock user
        return {
            "user_id": "jwt-user",
            "organization_id": "org-123",
            "role": "admin",
            "permissions": ["read", "write", "admin"],
        }
    
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_permission(permission: str):
    """Factory for permission-checking dependency"""
    async def check_permission(user: Dict = Depends(get_current_user)):
        if permission not in user.get("permissions", []) and "admin" not in user.get("permissions", []):
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")
        return user
    return check_permission


# =============================================================================
# HEALTH & STATUS ENDPOINTS
# =============================================================================

@app.get("/", tags=["Health"])
async def root():
    """API root - basic info"""
    return {
        "name": "VerityFlux Enterprise API",
        "version": "3.5.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "api": "healthy",
            "database": "healthy",
            "vulndb": "healthy",
            "scanner": "healthy",
            "soc": "healthy",
            "hitl": "healthy",
        },
    }


@app.get("/ready", tags=["Health"])
async def readiness_check():
    """Readiness check for Kubernetes"""
    # Check if all services are ready
    return {"ready": True}


# =============================================================================
# POLICY ENDPOINTS
# =============================================================================

@app.get("/api/v1/policy", response_model=PolicyResponse, tags=["Policy"])
async def get_policy(user: Dict = Depends(get_current_user)):
    """
    Get current policy file contents (if present).
    """
    policy = _load_policy()
    return PolicyResponse(
        policy=policy,
        path=str(_policy_path()),
        note="Policy is applied on service start; restart required after changes.",
    )


@app.post("/api/v1/policy", response_model=PolicyResponse, tags=["Policy"])
async def update_policy(body: PolicyUpdateRequest, user: Dict = Depends(get_current_user)):
    """
    Update policy file on disk (requires restart to take effect).
    """
    _require_admin(user)
    if not isinstance(body.policy, dict):
        raise HTTPException(status_code=400, detail="Policy must be a JSON object")
    _write_policy(body.policy)
    response = PolicyResponse(
        policy=_load_policy(),
        path=str(_policy_path()),
        note="Policy saved. Live reload available via /api/v1/policy/reload.",
    )
    _emit_integration_event(
        event_type="policy_updated",
        agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
        status="success",
        evidence={"path": response.path},
    )
    return response


@app.post("/api/v1/policy/reload", response_model=PolicyResponse, tags=["Policy"])
async def reload_policy(user: Dict = Depends(get_current_user)):
    """
    Reload policy file from disk. Applies to new firewall instances.
    """
    _require_admin(user)
    os.environ["VERITYFLUX_POLICY_PATH"] = str(_policy_path())
    policy = reload_all_policies(str(_policy_path()))
    response = PolicyResponse(
        policy=policy,
        path=str(_policy_path()),
        note="Policy reloaded. Live firewall instances updated.",
    )
    _emit_integration_event(
        event_type="policy_reloaded",
        agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
        status="success",
        evidence={"path": response.path},
    )
    return response


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login(request: LoginRequest):
    """
    Authenticate user and get access tokens
    """
    # In production:
    # result = await auth_service.authenticate_with_user_data(
    #     request.email, request.password, request.mfa_code
    # )
    
    # Mock response
    return LoginResponse(
        access_token="eyJ...",
        refresh_token="eyJ...",
        token_type="bearer",
        expires_in=1800,
        user_id="user-123",
        organization_id="org-123",
        role="admin",
    )


@app.post("/api/v1/auth/refresh", response_model=LoginResponse, tags=["Authentication"])
async def refresh_token(request: RefreshTokenRequest):
    """
    Refresh access token using refresh token
    """
    # result = await auth_service.refresh_session(request.refresh_token)
    
    return LoginResponse(
        access_token="eyJ...",
        refresh_token="eyJ...",
        token_type="bearer",
        expires_in=1800,
        user_id="user-123",
        organization_id="org-123",
        role="admin",
    )


@app.post("/api/v1/auth/logout", tags=["Authentication"])
async def logout(user: Dict = Depends(get_current_user)):
    """
    Logout and invalidate tokens
    """
    # await auth_service.logout(user["user_id"])
    return {"message": "Logged out successfully"}


@app.post("/api/v1/auth/api-keys", response_model=APIKeyResponse, tags=["Authentication"])
async def create_api_key(
    request: APIKeyCreateRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Create a new API key
    """
    # key, prefix, hash = await auth_service.create_api_key(...)
    
    return APIKeyResponse(
        key_id="key-123",
        key_prefix="vf_abc",
        api_key="vf_abc123def456...",  # Only shown once
        name=request.name,
        permissions=request.permissions,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=request.expires_in_days or 365),
    )


@app.get("/api/v1/auth/api-keys", response_model=List[APIKeyResponse], tags=["Authentication"])
async def list_api_keys(user: Dict = Depends(get_current_user)):
    """
    List user's API keys
    """
    return []


@app.delete("/api/v1/auth/api-keys/{key_id}", tags=["Authentication"])
async def revoke_api_key(key_id: str, user: Dict = Depends(get_current_user)):
    """
    Revoke an API key
    """
    return {"message": f"API key {key_id} revoked"}


# =============================================================================
# VULNERABILITY DATABASE ENDPOINTS
# =============================================================================

@app.get("/api/v1/vulnerabilities", response_model=PaginatedResponse, tags=["Vulnerabilities"])
async def list_vulnerabilities(
    query: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    tags: Optional[str] = None,  # Comma-separated
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    Search and list vulnerabilities
    """
    # tag_list = tags.split(",") if tags else None
    # results, total = vulndb_service.search_vulnerabilities(
    #     query=query, source=source, severity=severity,
    #     min_cvss=min_cvss, tags=tag_list, limit=limit, offset=offset
    # )
    
    # Mock response
    return PaginatedResponse(
        items=[],
        total=0,
        limit=limit,
        offset=offset,
        has_more=False,
    )


@app.get("/api/v1/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse, tags=["Vulnerabilities"])
async def get_vulnerability(
    vuln_id: str = Path(..., description="Vulnerability ID (e.g., LLM01, CVE-2024-1234)"),
    user: Dict = Depends(get_current_user)
):
    """
    Get vulnerability by ID
    """
    # vuln = vulndb_service.get_vulnerability(vuln_id)
    # if not vuln:
    #     raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    raise HTTPException(status_code=404, detail="Vulnerability not found")


@app.get("/api/v1/vulnerabilities/owasp/llm", response_model=List[VulnerabilityResponse], tags=["Vulnerabilities"])
async def get_owasp_llm_top_10(user: Dict = Depends(get_current_user)):
    """
    Get OWASP LLM Top 10 (2025)
    """
    # return vulndb_service.get_owasp_llm_top_10()
    return []


@app.get("/api/v1/vulnerabilities/owasp/agentic", response_model=List[VulnerabilityResponse], tags=["Vulnerabilities"])
async def get_owasp_agentic_top_10(user: Dict = Depends(get_current_user)):
    """
    Get OWASP Agentic Top 10 (2025)
    """
    # return vulndb_service.get_owasp_agentic_top_10()
    return []


@app.post("/api/v1/vulnerabilities/sync", response_model=List[VulnerabilitySyncResponse], tags=["Vulnerabilities"])
async def sync_vulnerabilities(
    background_tasks: BackgroundTasks,
    sources: Optional[List[str]] = Query(default=None, description="Sources to sync (nvd, atlas, github)"),
    user: Dict = Depends(get_current_user)
):
    """
    Trigger vulnerability database sync
    """
    # background_tasks.add_task(vulndb_service.sync_all_sources)
    return []


@app.get("/api/v1/vulnerabilities/stats", tags=["Vulnerabilities"])
async def get_vulnerability_stats(user: Dict = Depends(get_current_user)):
    """
    Get vulnerability database statistics
    """
    # return vulndb_service.get_statistics()
    return {
        "total_vulnerabilities": 0,
        "by_source": {},
        "by_severity": {},
    }


# =============================================================================
# SECURITY SCANNER ENDPOINTS
# =============================================================================

@app.post("/api/v1/scans", response_model=ScanStartResponse, tags=["Scanner"])
async def start_scan(
    payload: Dict[str, Any] = Body(...),
    background_tasks: BackgroundTasks = None,
    user: Dict = Depends(get_current_user)
):
    """
    Start a new security scan
    """
    scan_id = str(__import__("uuid").uuid4())

    # Accept either {"target": {...}, "config": {...}} or a flat target payload.
    if "target" in payload:
        target = ScanTargetRequest(**payload["target"])
        config = ScanConfigRequest(**payload.get("config", {})) if payload.get("config") else None
    else:
        target = ScanTargetRequest(**payload)
        config = None

    SCAN_STORE[scan_id] = {
        "status": "initializing",
        "started_at": datetime.utcnow(),
        "completed_at": None,
        "result": None,
        "error": None,
        "target_name": target.name,
        "profile": config.profile if config else "standard",
        "target_type": target.target_type,
    }

    if background_tasks is not None:
        background_tasks.add_task(_run_scan_job, scan_id, target, config, user)
    else:
        _run_scan_job(scan_id, target, config, user)

    _emit_integration_event(
        event_type="scan_started",
        agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
        status="success",
        evidence={"scan_id": scan_id, "target": target.name, "profile": config.profile if config else "standard"},
    )

    return ScanStartResponse(
        scan_id=scan_id,
        status="initializing",
        target_name=target.name,
        profile=config.profile if config else "standard",
        started_at=datetime.utcnow(),
        estimated_duration_minutes=10,
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResultResponse, tags=["Scanner"])
async def get_scan_result(
    scan_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get scan result by ID
    """
    scan = SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("result"):
        return scan["result"]
    return ScanResultResponse(
        scan_id=scan_id,
        status=scan.get("status", "unknown"),
        target_name=scan.get("target_name", "unknown"),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        duration_seconds=0.0,
        total_tests=0,
        passed_tests=0,
        failed_tests=0,
        overall_risk_score=0.0,
        risk_level="unknown",
        findings_summary={},
        findings=[],
    )


@app.get("/api/v1/scans/{scan_id}/progress", response_model=ScanProgressResponse, tags=["Scanner"])
async def get_scan_progress(
    scan_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get real-time scan progress
    """
    scan = SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    status = scan.get("status", "unknown")
    progress = 100.0 if status == "completed" else 10.0 if status == "running" else 0.0
    return ScanProgressResponse(
        scan_id=scan_id,
        status=status,
        progress_percent=progress,
        completed_tests=0,
        total_tests=0,
        current_vuln="",
        findings_count=len(scan.get("result").findings) if scan.get("result") else 0,
        elapsed_seconds=(datetime.utcnow() - scan.get("started_at")).total_seconds() if scan.get("started_at") else 0.0,
        estimated_remaining_seconds=None,
    )


@app.post("/api/v1/scans/{scan_id}/cancel", tags=["Scanner"])
async def cancel_scan(
    scan_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Cancel a running scan
    """
    # await scanner_service.cancel_scan(scan_id)
    return {"message": f"Scan {scan_id} cancelled"}


@app.get("/api/v1/scans/{scan_id}/findings", response_model=List[ScanFindingResponse], tags=["Scanner"])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    user: Dict = Depends(get_current_user)
):
    """
    Get findings from a scan
    """
    scan = SCAN_STORE.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = scan["result"].findings
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


@app.get("/api/v1/scans/{scan_id}/report", tags=["Scanner"])
async def get_scan_report(
    scan_id: str,
    format: str = Query(default="json", description="Report format: json, pdf, sarif"),
    user: Dict = Depends(get_current_user)
):
    """
    Download scan report
    """
    scan = SCAN_STORE.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(status_code=404, detail="Scan not found")
    if format != "json":
        raise HTTPException(status_code=400, detail="Only json format is supported in demo mode")
    return scan["result"]
    # result = scanner_service.get_result(scan_id)
    # if format == "json":
    #     return ScanReportGenerator.to_json(result)
    # elif format == "sarif":
    #     return ScanReportGenerator.to_sarif(result)
    
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/v1/scans", response_model=PaginatedResponse, tags=["Scanner"])
async def list_scans(
    status: Optional[str] = None,
    limit: int = Query(default=20, le=100),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List scan history
    """
    rows: List[Dict[str, Any]] = []
    for scan_id, scan in SCAN_STORE.items():
        if status and scan.get("status") != status:
            continue
        result = scan.get("result")
        findings_summary = {}
        overall_risk_score = None
        if result:
            findings_summary = result.findings_summary
            overall_risk_score = result.overall_risk_score
        rows.append({
            "scan_id": scan_id,
            "status": scan.get("status", "unknown"),
            "target_name": scan.get("target_name", "unknown"),
            "target_type": scan.get("target_type", "unknown"),
            "profile": scan.get("profile", "standard"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "overall_risk_score": overall_risk_score,
            "findings_summary": findings_summary,
            "error": scan.get("error"),
        })

    rows.sort(key=lambda r: (r.get("started_at") or datetime.min), reverse=True)
    total = len(rows)
    items = rows[offset: offset + limit]
    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


# =============================================================================
# SOC COMMAND CENTER ENDPOINTS
# =============================================================================

# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------

@app.post("/api/v1/soc/events", tags=["SOC"])
async def ingest_security_event(
    event: SecurityEventRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Ingest a security event from an agent
    """
    # security_event = SecurityEvent(
    #     organization_id=user["organization_id"],
    #     agent_id=event.agent_id,
    #     ...
    # )
    # alert = await soc_service.process_event(security_event)
    
    return {
        "event_id": str(__import__("uuid").uuid4()),
        "processed": True,
        "alert_created": False,
    }


@app.get("/api/v1/soc/events", response_model=PaginatedResponse, tags=["SOC"])
async def list_security_events(
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List security events
    """
    return PaginatedResponse(
        items=[],
        total=0,
        limit=limit,
        offset=offset,
        has_more=False,
    )


# -----------------------------------------------------------------------------
# Alerts
# -----------------------------------------------------------------------------

@app.get("/api/v1/soc/alerts", response_model=PaginatedResponse, tags=["SOC"])
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List security alerts
    """
    # alerts, total = soc_service.list_alerts(
    #     organization_id=user["organization_id"],
    #     status=AlertStatus(status) if status else None,
    #     ...
    # )
    
    return PaginatedResponse(
        items=[],
        total=0,
        limit=limit,
        offset=offset,
        has_more=False,
    )


@app.get("/api/v1/soc/alerts/{alert_id}", response_model=AlertResponse, tags=["SOC"])
async def get_alert(
    alert_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get alert by ID
    """
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/v1/soc/alerts/{alert_id}/acknowledge", tags=["SOC"])
async def acknowledge_alert(
    alert_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Acknowledge an alert
    """
    # soc_service.acknowledge_alert(alert_id, user["user_id"])
    return {"message": "Alert acknowledged"}


@app.post("/api/v1/soc/alerts/{alert_id}/escalate", response_model=IncidentResponse, tags=["SOC"])
async def escalate_alert_to_incident(
    alert_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Escalate alert to incident
    """
    # incident = soc_service.escalate_alert_to_incident(alert_id, user["user_id"])
    raise HTTPException(status_code=404, detail="Alert not found")


# -----------------------------------------------------------------------------
# Incidents
# -----------------------------------------------------------------------------

@app.post("/api/v1/soc/incidents", response_model=IncidentResponse, tags=["SOC"])
async def create_incident(
    request: IncidentCreateRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Create a new incident manually
    """
    # incident = soc_service.incident_manager.create_incident(
    #     title=request.title,
    #     description=request.description,
    #     incident_type=IncidentType(request.incident_type),
    #     priority=IncidentPriority(request.priority),
    #     organization_id=user["organization_id"],
    #     created_by=user["user_id"],
    #     affected_agents=request.affected_agents,
    #     related_alerts=request.related_alerts,
    # )
    
    return IncidentResponse(
        id=str(__import__("uuid").uuid4()),
        number="INC-2026-00001",
        title=request.title,
        description=request.description,
        incident_type=request.incident_type,
        priority=request.priority,
        status="open",
        created_at=datetime.utcnow(),
        acknowledged_at=None,
        resolved_at=None,
        assigned_to=None,
        sla_response_breached=False,
        sla_resolution_breached=False,
        affected_agents=request.affected_agents,
        impact_score=0,
    )


@app.get("/api/v1/soc/incidents", response_model=PaginatedResponse, tags=["SOC"])
async def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List incidents
    """
    return PaginatedResponse(
        items=[],
        total=0,
        limit=limit,
        offset=offset,
        has_more=False,
    )


@app.get("/api/v1/soc/incidents/{incident_id}", response_model=IncidentResponse, tags=["SOC"])
async def get_incident(
    incident_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get incident by ID
    """
    raise HTTPException(status_code=404, detail="Incident not found")


@app.patch("/api/v1/soc/incidents/{incident_id}", response_model=IncidentResponse, tags=["SOC"])
async def update_incident(
    incident_id: str,
    request: IncidentUpdateRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Update incident (status, assignment, etc.)
    """
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/v1/soc/incidents/{incident_id}/acknowledge", tags=["SOC"])
async def acknowledge_incident(
    incident_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Acknowledge an incident
    """
    # soc_service.incident_manager.acknowledge_incident(incident_id, user["user_id"])
    return {"message": "Incident acknowledged"}


@app.post("/api/v1/soc/incidents/{incident_id}/assign", tags=["SOC"])
async def assign_incident(
    incident_id: str,
    assignee: str = Body(..., embed=True),
    user: Dict = Depends(get_current_user)
):
    """
    Assign incident to a user
    """
    return {"message": f"Incident assigned to {assignee}"}


@app.post("/api/v1/soc/incidents/{incident_id}/resolve", tags=["SOC"])
async def resolve_incident(
    incident_id: str,
    root_cause: str = Body(...),
    resolution_summary: str = Body(...),
    remediation_steps: List[str] = Body(default=[]),
    user: Dict = Depends(get_current_user)
):
    """
    Resolve an incident
    """
    return {"message": "Incident resolved"}


@app.post("/api/v1/soc/incidents/{incident_id}/comments", tags=["SOC"])
async def add_incident_comment(
    incident_id: str,
    content: str = Body(..., embed=True),
    is_internal: bool = Body(default=True),
    user: Dict = Depends(get_current_user)
):
    """
    Add comment to incident
    """
    return {"message": "Comment added"}


@app.get("/api/v1/soc/incidents/{incident_id}/timeline", tags=["SOC"])
async def get_incident_timeline(
    incident_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get incident timeline
    """
    return {"timeline": []}


# -----------------------------------------------------------------------------
# Agents
# -----------------------------------------------------------------------------

@app.post("/api/v1/soc/agents", response_model=AgentResponse, tags=["SOC"])
async def register_agent(
    request: AgentRegisterRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Register a new agent for monitoring
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    normalized_name = request.name.strip()
    if not normalized_name:
        raise HTTPException(status_code=400, detail="Agent name is required")

    # Idempotent registration by (org_id, name).
    existing = None
    for record in AGENT_STORE.values():
        if record.get("organization_id") == org_id and str(record.get("name")).lower() == normalized_name.lower():
            existing = record
            break

    if existing:
        existing["agent_type"] = request.agent_type
        existing["model_provider"] = request.model_provider
        existing["model_name"] = request.model_name
        existing["tools"] = list(request.tools or [])
        existing["environment"] = request.environment
        existing["updated_at"] = datetime.utcnow()
        _save_agent_store()
        _emit_integration_event(
            event_type="agent_updated",
            agent_id=str(existing.get("id")),
            status="success",
            evidence={"name": existing.get("name"), "environment": existing.get("environment")},
        )
        return _agent_to_response(existing)

    agent_id = str(uuid.uuid4())
    record = {
        "id": agent_id,
        "organization_id": org_id,
        "name": normalized_name,
        "agent_type": request.agent_type,
        "status": "healthy",
        "model_provider": request.model_provider,
        "model_name": request.model_name,
        "tools": list(request.tools or []),
        "environment": request.environment,
        "total_requests": 0,
        "blocked_requests": 0,
        "health_score": 100.0,
        "last_seen_at": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    AGENT_STORE[agent_id] = record
    _save_agent_store()
    _emit_integration_event(
        event_type="agent_registered",
        agent_id=agent_id,
        status="success",
        evidence={"name": normalized_name, "environment": request.environment},
    )
    return _agent_to_response(record)


@app.get("/api/v1/soc/agents", response_model=PaginatedResponse, tags=["SOC"])
async def list_agents(
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List monitored agents
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    rows = [r for r in AGENT_STORE.values() if r.get("organization_id") == org_id]
    if status:
        rows = [r for r in rows if str(r.get("status", "")).lower() == status.lower()]
    rows.sort(key=lambda r: r.get("updated_at") or datetime.min, reverse=True)
    total = len(rows)
    sliced = rows[offset: offset + limit]
    items = [_agent_to_response(r).model_dump() for r in sliced]
    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.get("/api/v1/soc/agents/{agent_id}", response_model=AgentResponse, tags=["SOC"])
async def get_agent(
    agent_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get agent by ID
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    record = AGENT_STORE.get(agent_id)
    if not record or record.get("organization_id") != org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_response(record)


@app.get("/api/v1/soc/agents/{agent_id}/metrics", tags=["SOC"])
async def get_agent_metrics(
    agent_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get agent metrics
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    record = AGENT_STORE.get(agent_id)
    if not record or record.get("organization_id") != org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    total_requests = int(record.get("total_requests", 0) or 0)
    blocked_requests = int(record.get("blocked_requests", 0) or 0)
    allowed = max(0, total_requests - blocked_requests)
    block_rate = (blocked_requests / total_requests * 100.0) if total_requests > 0 else 0.0
    return {
        "agent_id": agent_id,
        "status": record.get("status", "healthy"),
        "health_score": float(record.get("health_score", 100.0) or 0.0),
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed,
        "block_rate_percent": round(block_rate, 2),
        "last_seen_at": record.get("last_seen_at"),
        "tools_count": len(record.get("tools", []) or []),
    }


@app.post("/api/v1/soc/agents/{agent_id}/heartbeat", tags=["SOC"])
async def agent_heartbeat(
    agent_id: str,
    blocked: bool = Body(default=False, embed=True),
    user: Dict = Depends(get_current_user)
):
    """
    Record agent heartbeat
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    record = AGENT_STORE.get(agent_id)
    if not record or record.get("organization_id") != org_id:
        raise HTTPException(status_code=404, detail="Agent not found")

    record["last_seen_at"] = datetime.utcnow()
    record["total_requests"] = int(record.get("total_requests", 0) or 0) + 1
    if blocked:
        record["blocked_requests"] = int(record.get("blocked_requests", 0) or 0) + 1
        record["health_score"] = max(0.0, float(record.get("health_score", 100.0) or 0.0) - 1.0)
    else:
        record["health_score"] = min(100.0, float(record.get("health_score", 100.0) or 0.0) + 0.1)
    record["updated_at"] = datetime.utcnow()
    _save_agent_store()
    return {"received": True, "agent_id": agent_id, "blocked": blocked}


@app.post("/api/v1/soc/agents/{agent_id}/quarantine", tags=["SOC"])
async def quarantine_agent(
    agent_id: str,
    reason: str = Body(..., embed=True),
    user: Dict = Depends(get_current_user)
):
    """
    Quarantine an agent
    """
    org_id = user.get("organization_id", "default-org") if isinstance(user, dict) else "default-org"
    record = AGENT_STORE.get(agent_id)
    if not record or record.get("organization_id") != org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    record["status"] = "quarantined"
    record["health_score"] = min(float(record.get("health_score", 100.0) or 0.0), 25.0)
    record["updated_at"] = datetime.utcnow()
    _save_agent_store()
    _emit_integration_event(
        event_type="agent_quarantined",
        agent_id=agent_id,
        status="denied",
        reason=reason,
        evidence={"name": record.get("name"), "reason": reason},
    )
    return {"message": f"Agent {agent_id} quarantined", "reason": reason}


# -----------------------------------------------------------------------------
# Metrics & Dashboard
# -----------------------------------------------------------------------------

@app.get("/api/v1/soc/metrics", response_model=SOCMetricsResponse, tags=["SOC"])
async def get_soc_metrics(
    period: str = Query(default="24h", description="Time period: 1h, 24h, 7d, 30d"),
    user: Dict = Depends(get_current_user)
):
    """
    Get SOC dashboard metrics
    """
    # metrics = soc_service.get_metrics(organization_id=user["organization_id"], period=period)
    # threat_level = soc_service.get_threat_level(user["organization_id"])
    
    return SOCMetricsResponse(
        timestamp=datetime.utcnow(),
        period=period,
        incidents={"total": 0, "open": 0, "by_priority": {}, "by_status": {}},
        sla={"compliance_rate": 100.0, "avg_response_time_minutes": 0, "breaches": 0},
        events={"total": 0, "blocked": 0, "allowed": 0},
        alerts={"total": 0, "new": 0},
        agents={"total": 0, "healthy": 0, "unhealthy": 0},
        threat_level="green",
    )


@app.get("/api/v1/soc/threat-level", tags=["SOC"])
async def get_threat_level(user: Dict = Depends(get_current_user)):
    """
    Get current threat level
    """
    # return {"threat_level": soc_service.get_threat_level(user["organization_id"])}
    return {"threat_level": "green"}


# =============================================================================
# HITL APPROVAL ENDPOINTS
# =============================================================================

@app.post("/api/v1/approvals", response_model=ApprovalRequestResponse, tags=["HITL"])
async def request_approval(
    context: ApprovalContextRequest,
    approval_type: str = Query(default="tool_execution"),
    timeout_minutes: Optional[int] = None,
    wait: bool = Query(default=False, description="Wait for decision"),
    user: Dict = Depends(get_current_user)
):
    """
    Request human approval for an action
    """
    # approval_context = ApprovalContext(
    #     agent_id=context.agent_id,
    #     ...
    #     organization_id=user["organization_id"],
    # )
    # status, request = await hitl_service.request_approval(
    #     context=approval_context,
    #     approval_type=ApprovalType(approval_type),
    #     timeout_minutes=timeout_minutes,
    #     wait_for_decision=wait,
    # )
    
    request_id = str(__import__("uuid").uuid4())
    
    return ApprovalRequestResponse(
        id=request_id,
        status="pending",
        risk_level="medium",
        title=f"{context.agent_name} wants to use {context.tool_name}",
        description=f"Risk score: {context.risk_score}",
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=timeout_minutes or 30),
        time_remaining_seconds=1800,
        assigned_to=["admin"],
        decision=None,
        decided_by=None,
        justification=None,
    )


@app.get("/api/v1/approvals", response_model=PaginatedResponse, tags=["HITL"])
async def list_approval_requests(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(get_current_user)
):
    """
    List approval requests
    """
    return PaginatedResponse(
        items=[],
        total=0,
        limit=limit,
        offset=offset,
        has_more=False,
    )


@app.get("/api/v1/approvals/pending", response_model=List[ApprovalRequestResponse], tags=["HITL"])
async def get_pending_approvals(user: Dict = Depends(get_current_user)):
    """
    Get pending approvals assigned to current user
    """
    # return hitl_service.get_pending_for_user(user["user_id"])
    return []


@app.get("/api/v1/approvals/{request_id}", response_model=ApprovalRequestResponse, tags=["HITL"])
async def get_approval_request(
    request_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get approval request by ID
    """
    raise HTTPException(status_code=404, detail="Approval request not found")


@app.post("/api/v1/approvals/{request_id}/decide", tags=["HITL"])
async def decide_approval(
    request_id: str,
    request: ApprovalDecisionRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Make a decision on an approval request
    """
    # success, message = await hitl_service.process_decision(
    #     request_id=request_id,
    #     decision=ApprovalDecision(request.decision),
    #     decided_by=user["user_id"],
    #     justification=request.justification,
    #     conditions=request.conditions,
    # )
    
    return {"success": True, "message": f"Request {request.decision}"}


@app.post("/api/v1/approvals/{request_id}/cancel", tags=["HITL"])
async def cancel_approval_request(
    request_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Cancel a pending approval request
    """
    # hitl_service.cancel_request(request_id, user["user_id"])
    return {"message": "Request cancelled"}


@app.post("/api/v1/approvals/bulk/approve", tags=["HITL"])
async def bulk_approve(
    request_ids: List[str] = Body(...),
    justification: str = Body(...),
    user: Dict = Depends(get_current_user)
):
    """
    Bulk approve multiple requests
    """
    # results = await hitl_service.bulk_approve(request_ids, user["user_id"], justification)
    return {"approved": len(request_ids), "results": {}}


@app.post("/api/v1/approvals/bulk/deny", tags=["HITL"])
async def bulk_deny(
    request_ids: List[str] = Body(...),
    justification: str = Body(...),
    user: Dict = Depends(get_current_user)
):
    """
    Bulk deny multiple requests
    """
    return {"denied": len(request_ids), "results": {}}


# -----------------------------------------------------------------------------
# Policies & Rules
# -----------------------------------------------------------------------------

@app.post("/api/v1/approvals/policies", tags=["HITL"])
async def create_approval_policy(
    request: ApprovalPolicyRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Create an approval policy
    """
    return {"policy_id": str(__import__("uuid").uuid4()), "name": request.name}


@app.get("/api/v1/approvals/policies", tags=["HITL"])
async def list_approval_policies(user: Dict = Depends(get_current_user)):
    """
    List approval policies
    """
    return {"policies": []}


@app.get("/api/v1/approvals/rules", tags=["HITL"])
async def list_approval_rules(
    rule_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    user: Dict = Depends(get_current_user)
):
    """
    List approval rules
    """
    return {"rules": []}


@app.delete("/api/v1/approvals/rules/{rule_id}", tags=["HITL"])
async def delete_approval_rule(
    rule_id: str,
    user: Dict = Depends(get_current_user)
):
    """
    Delete an approval rule
    """
    return {"message": "Rule deleted"}


@app.get("/api/v1/approvals/stats", response_model=ApprovalStatsResponse, tags=["HITL"])
async def get_approval_stats(
    period_hours: int = Query(default=24),
    user: Dict = Depends(get_current_user)
):
    """
    Get approval statistics
    """
    # stats = hitl_service.get_stats(user["organization_id"], period_hours)
    
    return ApprovalStatsResponse(
        total_requests=0,
        by_status={},
        by_type={},
        auto_approved=0,
        auto_denied=0,
        avg_decision_time_seconds=0,
    )


# =============================================================================
# INTEGRATION ENDPOINTS
# =============================================================================

@app.post("/api/v1/integrations", response_model=IntegrationResponse, tags=["Integrations"])
async def create_integration(
    request: IntegrationConfigRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Create a new integration
    """
    # integration_manager.register_integration(
    #     name=request.name,
    #     integration_type=IntegrationType(request.integration_type),
    #     config=request.config,
    # )
    
    return IntegrationResponse(
        name=request.name,
        integration_type=request.integration_type,
        enabled=request.enabled,
        status="configured",
        last_used_at=None,
    )


@app.get("/api/v1/integrations", response_model=List[IntegrationResponse], tags=["Integrations"])
async def list_integrations(user: Dict = Depends(get_current_user)):
    """
    List configured integrations
    """
    # return integration_manager.list_integrations()
    return []


@app.get("/api/v1/integrations/{name}", response_model=IntegrationResponse, tags=["Integrations"])
async def get_integration(
    name: str,
    user: Dict = Depends(get_current_user)
):
    """
    Get integration by name
    """
    raise HTTPException(status_code=404, detail="Integration not found")


@app.delete("/api/v1/integrations/{name}", tags=["Integrations"])
async def delete_integration(
    name: str,
    user: Dict = Depends(get_current_user)
):
    """
    Delete an integration
    """
    return {"message": f"Integration {name} deleted"}


@app.post("/api/v1/integrations/{name}/test", tags=["Integrations"])
async def test_integration(
    name: str,
    user: Dict = Depends(get_current_user)
):
    """
    Test integration connection
    """
    # integration = integration_manager.get_integration(name)
    # success, message = await integration.test_connection()
    
    return {"success": True, "message": "Connection successful"}


@app.post("/api/v1/notifications/send", tags=["Integrations"])
async def send_notification(
    request: NotificationRequest,
    user: Dict = Depends(get_current_user)
):
    """
    Send a notification through integrations
    """
    # notification = Notification(
    #     notification_type=NotificationType(request.notification_type),
    #     priority=NotificationPriority(request.priority),
    #     title=request.title,
    #     message=request.message,
    #     details=request.details,
    # )
    # results = await integration_manager.send_notification(notification, request.integrations)
    
    return {"sent": True, "results": {}}


# =============================================================================
# WEBHOOK ENDPOINTS
# =============================================================================

@app.post("/api/v1/webhooks/slack/interactive", tags=["Webhooks"])
async def slack_interactive_webhook(request: Request):
    """
    Handle Slack interactive component callbacks (button clicks)
    """
    # Verify Slack signature
    # Parse payload
    # Process approval decision
    
    body = await request.body()
    # payload = json.loads(body)
    
    return {"ok": True}


@app.post("/api/v1/webhooks/slack/events", tags=["Webhooks"])
async def slack_events_webhook(request: Request):
    """
    Handle Slack Events API
    """
    body = await request.json()
    
    # Handle URL verification challenge
    if body.get("type") == "url_verification":
        return {"challenge": body.get("challenge")}
    
    return {"ok": True}


@app.post("/api/v1/webhooks/stripe", tags=["Webhooks"])
async def stripe_webhook(request: Request):
    """
    Handle Stripe webhooks for subscription updates
    """
    # Verify Stripe signature
    # Process event
    
    return {"received": True}


@app.post("/api/v1/webhooks/jira", tags=["Webhooks"])
async def jira_webhook(request: WebhookEventRequest):
    """
    Handle Jira webhooks for ticket updates
    """
    return {"received": True}


@app.post("/api/v1/webhooks/pagerduty", tags=["Webhooks"])
async def pagerduty_webhook(request: WebhookEventRequest):
    """
    Handle PagerDuty webhooks
    """
    return {"received": True}


# =============================================================================
# WEBSOCKET ENDPOINTS
# =============================================================================

class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        self.active_connections[channel].append(websocket)
    
    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.active_connections:
            self.active_connections[channel].remove(websocket)
    
    async def broadcast(self, channel: str, message: Dict):
        if channel in self.active_connections:
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except:
                    pass


ws_manager = ConnectionManager()


@app.websocket("/ws/events/{organization_id}")
async def websocket_events(websocket: WebSocket, organization_id: str):
    """
    WebSocket for real-time security events
    """
    await ws_manager.connect(websocket, f"events:{organization_id}")
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Handle ping/pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"events:{organization_id}")


@app.websocket("/ws/approvals/{user_id}")
async def websocket_approvals(websocket: WebSocket, user_id: str):
    """
    WebSocket for real-time approval notifications
    """
    await ws_manager.connect(websocket, f"approvals:{user_id}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"approvals:{user_id}")


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """
    WebSocket for real-time scan progress
    """
    await ws_manager.connect(websocket, f"scan:{scan_id}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"scan:{scan_id}")


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "code": str(exc.status_code)},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "500"},
    )


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "api.v2.main:app",
        host="0.0.0.0",
        port=int(os.getenv("VERITYFLUX_PORT", "8003")),
        reload=True,
        log_level="info",
    )

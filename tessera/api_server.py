#!/usr/bin/env python3
"""
Tessera API - MINIMAL WORKING VERSION
Only uses methods that actually exist in Tessera

Save as: ~/ml-redteam/tessera/api_server.py
"""

import os
import sys
import json
import hashlib
import hmac
import time
from datetime import datetime, UTC
from urllib import request as urllib_request
from pathlib import Path

# Environment defaults
def _prod_mode() -> bool:
    return os.getenv("MLRT_MODE", "").lower() == "prod" or os.getenv("MODE", "").lower() == "prod"


def _strict_prod_mode() -> bool:
    return _prod_mode() and os.getenv("SUITE_STRICT_MODE", "false").lower() in ("1", "true", "yes")


if not os.getenv('TESSERA_SECRET_KEY') and not _strict_prod_mode():
    os.environ['TESSERA_SECRET_KEY'] = '168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06'
# DPoP and memory binding are opt-in for production deployments
if not os.getenv('TESSERA_REQUIRE_DPOP'):
    os.environ['TESSERA_REQUIRE_DPOP'] = 'false'
if not os.getenv('TESSERA_REQUIRE_MEMORY_BINDING'):
    os.environ['TESSERA_REQUIRE_MEMORY_BINDING'] = 'false'
if not os.getenv('TESSERA_REQUIRE_ACTION_SIGNATURE'):
    os.environ['TESSERA_REQUIRE_ACTION_SIGNATURE'] = 'true'

if _prod_mode():
    os.environ.setdefault("TESSERA_REQUIRE_DPOP", "true")
    os.environ.setdefault("TESSERA_REQUIRE_MEMORY_BINDING", "true")
    os.environ.setdefault("TESSERA_REQUIRE_ACTION_SIGNATURE", "true")

sys.path.insert(0, str(Path(__file__).parent))

print("🔐 Starting Tessera IAM API Server...")

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn

# Tessera
from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper, AccessDecision
from tessera.dpop_replay_cache import DPoPReplayCache
import jwt
from tessera.rate_limiter import RateLimiter

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    Counter = Histogram = generate_latest = CONTENT_TYPE_LATEST = None
METRICS_TOKEN_REQUESTS = METRICS_TOKEN_VALIDATIONS = METRICS_TOKEN_REVOCATIONS = METRICS_ACCESS_DENIALS = METRICS_REQUEST_DURATION = None
SECURITY_EFFICACY = {
    "validations_total": 0,
    "allowed_total": 0,
    "denied_total": 0,
    "denied_by_reason": {},
}
from tessera.revocation import RevocationList
from tessera.delegation_chain import DelegationChain
from tessera.session_store import SessionStateStore
from tessera.memory_guard import SessionMemoryGuard
from tessera.audit_logger import AuditChainLogger

print("✅ Tessera imports successful")

# Vestigia
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from vestigia_bridge import VestigiaBridge
    vestigia = VestigiaBridge()
    VESTIGIA_AVAILABLE = True
    print("✅ Vestigia connected")
except:
    VESTIGIA_AVAILABLE = False
    class VestigiaBridge:
        def log_token_issued(self, *a, **k): pass
        def log_token_validated(self, *a, **k): pass
        def log_token_revoked(self, *a, **k): pass
    vestigia = VestigiaBridge()
    print("⚠️  Vestigia unavailable")

# VerityFlux bridge is initialised after gatekeeper (below)
VERITYFLUX_AVAILABLE = False
verityflux_bridge = None

# ---------------------------------------------------------------------------
# Integration hooks (opt-in)
# ---------------------------------------------------------------------------

def _integration_enabled() -> bool:
    return os.getenv("MLRT_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes")

def _header_value(request: Optional[Request], *names: str) -> Optional[str]:
    if not request:
        return None
    for name in names:
        value = request.headers.get(name)
        if value:
            return value
    return None


def _normalize_correlation(
    *,
    agent_id: Optional[str],
    event_type: str,
    session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> tuple[str, str]:
    sid = session_id or correlation_id
    if not sid:
        sid = f"{agent_id or 'unknown'}:{event_type}"
    tid = trace_id or correlation_id or sid
    return sid, tid


def _tool_registry_path() -> Path:
    raw = os.getenv("TOOL_REGISTRY_PATH", str(Path(__file__).parent.parent / "shared_state" / "tool_registry.json"))
    return Path(raw)


def _load_tool_registry() -> dict:
    path = _tool_registry_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _tool_allowlist() -> Optional[set]:
    raw = os.getenv("TOOL_ALLOWLIST")
    if not raw:
        return None
    return {t.strip() for t in raw.split(",") if t.strip()}


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _verify_tool_signature(entry: dict) -> bool:
    key = os.getenv("TOOL_REGISTRY_SIGNING_KEY", "")
    if not key:
        return False
    sig = entry.get("signature")
    if not sig:
        return False
    payload = dict(entry)
    payload.pop("signature", None)
    mac = hmac.new(key.encode("utf-8"), _canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, str(sig))


def _tool_allowed(tool_name: str) -> bool:
    allowlist = _tool_allowlist()
    if allowlist is not None and tool_name not in allowlist:
        return False
    registry = _load_tool_registry()
    tools = registry.get("tools") if isinstance(registry, dict) else None
    if not isinstance(tools, dict):
        return True
    entry = tools.get(tool_name)
    if not entry:
        return not os.getenv("TOOL_REGISTRY_ENFORCE", "false").lower() in ("1", "true", "yes")
    if os.getenv("TOOL_REGISTRY_ENFORCE", "false").lower() in ("1", "true", "yes"):
        return _verify_tool_signature(entry)
    return True


def _validate_tool_params(tool_name: str, params: dict) -> Optional[str]:
    registry = _load_tool_registry()
    tools = registry.get("tools") if isinstance(registry, dict) else None
    if not isinstance(tools, dict):
        return None
    entry = tools.get(tool_name) or {}
    schema = entry.get("schema") if isinstance(entry, dict) else None
    if not isinstance(schema, dict):
        return None
    max_bytes = int(schema.get("max_param_bytes") or 0)
    if max_bytes > 0:
        try:
            size = len(json.dumps(params).encode("utf-8"))
            if size > max_bytes:
                return "tool parameters exceed max size"
        except Exception:
            return "tool parameters invalid"
    required = schema.get("required") or []
    forbidden = schema.get("forbidden") or []
    if isinstance(required, list):
        for key in required:
            if key not in params:
                return f"missing required parameter: {key}"
    if isinstance(forbidden, list):
        for key in forbidden:
            if key in params:
                return f"forbidden parameter present: {key}"
    return None


def _validate_contract_event(event: dict) -> bool:
    required = ["timestamp", "source", "event_type", "outcome"]
    for key in required:
        if key not in event:
            return False
    if not isinstance(event.get("outcome"), dict) or "status" not in event["outcome"]:
        return False
    return True


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _cap_memory_ttl(ttl_seconds: int) -> int:
    if TESSERA_MEMORY_TTL_MAX <= 0:
        return max(1, ttl_seconds)
    return max(1, min(int(ttl_seconds), TESSERA_MEMORY_TTL_MAX))


def _denial_blocked(agent_id: str) -> bool:
    entry = _denial_state.get(agent_id)
    if not entry:
        return False
    if entry["reset_at"] <= time.time():
        return False
    return entry["count"] >= TESSERA_DENIAL_THRESHOLD


def _record_denial(agent_id: str) -> None:
    now = time.time()
    entry = _denial_state.get(agent_id)
    if not entry or entry["reset_at"] <= now:
        entry = {"count": 0, "reset_at": now + TESSERA_DENIAL_WINDOW_SECONDS}
    entry["count"] += 1
    _denial_state[agent_id] = entry


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

    try:
        req = urllib_request.Request(
            ingest_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=2) as _:
            pass
    except Exception:
        # Best-effort only; never fail core flows.
        return


def _emit_integration_event(
    *,
    event_type: str,
    agent_id: str,
    status: str,
    tool: Optional[str] = None,
    evidence: Optional[dict] = None,
    reason: Optional[str] = None,
    session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    if not _integration_enabled():
        return
    session_id, trace_id = _normalize_correlation(
        agent_id=agent_id,
        event_type=event_type,
        session_id=session_id,
        trace_id=trace_id,
        correlation_id=correlation_id,
    )
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "tessera",
        "event_type": event_type,
        "actor": {"agent_id": agent_id},
        "request": {"session_id": session_id, "trace_id": trace_id},
        "outcome": {"status": status, "reason": reason},
        "evidence": evidence or {},
    }
    if tool:
        event["evidence"]["tool"] = tool
    _send_to_vestigia(event)

# Initialize
app = FastAPI(title="Tessera IAM", version="2.0")
registry = TesseraRegistry()
token_gen = TokenGenerator(registry)
revocation = RevocationList()
gatekeeper = Gatekeeper(token_gen, revocation, registry=registry)
session_store = SessionStateStore()
audit_logger = AuditChainLogger()
dpop_replay_cache = DPoPReplayCache()
action_replay_cache = DPoPReplayCache()
rate_limiter = RateLimiter()
_denial_state = {}

# Guardrail defaults
TESSERA_ACTION_REPLAY_TTL = int(os.getenv("TESSERA_ACTION_REPLAY_TTL", "300"))
TESSERA_MEMORY_TTL_MAX = int(os.getenv("TESSERA_MEMORY_TTL_MAX", "3600"))
TESSERA_ACCESS_RATE_LIMIT = int(os.getenv("TESSERA_ACCESS_RATE_LIMIT", "120"))
TESSERA_ACCESS_WINDOW_SECONDS = int(os.getenv("TESSERA_ACCESS_WINDOW_SECONDS", "60"))
TESSERA_DENIAL_THRESHOLD = int(os.getenv("TESSERA_DENIAL_THRESHOLD", "5"))
TESSERA_DENIAL_WINDOW_SECONDS = int(os.getenv("TESSERA_DENIAL_WINDOW_SECONDS", "300"))
TESSERA_DELEGATION_TTL_SECONDS = int(os.getenv("TESSERA_DELEGATION_TTL_SECONDS", "300"))
TESSERA_REQUIRE_TRUSTED_CONTEXT = os.getenv("TESSERA_REQUIRE_TRUSTED_CONTEXT", "false").lower() in ("1", "true", "yes")
_trusted_ctx_env = os.getenv("TESSERA_TRUSTED_CONTEXT_LEVELS", "trusted,internal")
TESSERA_TRUSTED_CONTEXT_LEVELS = {t.strip().lower() for t in _trusted_ctx_env.split(",") if t.strip()}

if Counter:
    METRICS_TOKEN_REQUESTS = Counter("tessera_token_requests_total", "Token requests")
    METRICS_TOKEN_VALIDATIONS = Counter("tessera_token_validations_total", "Token validations")
    METRICS_TOKEN_REVOCATIONS = Counter("tessera_token_revocations_total", "Token revocations")
    METRICS_ACCESS_DENIALS = Counter("tessera_access_denials_total", "Access denials", ["reason"])
    METRICS_REQUEST_DURATION = Histogram("tessera_request_duration_seconds", "Request duration", ["endpoint"])

delegation_chain = DelegationChain(token_generator=token_gen)

# Now initialise VerityFlux bridge (needs gatekeeper)
# NOTE: Cannot use plain `from integration.verityflux_bridge import ...` because
# Vestigia also has an `integration/` package on sys.path which shadows ours.
# Use importlib with an explicit file path instead.
try:
    import importlib.util as _ilu
    _bridge_path = Path(__file__).parent / "integration" / "verityflux_bridge.py"
    _spec = _ilu.spec_from_file_location("tessera_verityflux_bridge", _bridge_path)
    _bridge_mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_bridge_mod)
    TesseraVerityFluxBridge = _bridge_mod.TesseraVerityFluxBridge
    verityflux_bridge = TesseraVerityFluxBridge(gatekeeper)
    VERITYFLUX_AVAILABLE = True
    print("✅ VerityFlux bridge connected")
except Exception as e:
    VERITYFLUX_AVAILABLE = False
    verityflux_bridge = None
    print(f"⚠️  VerityFlux bridge unavailable: {e}")

print("✅ Components initialized")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session memory guard (skip health + token issuance)
app.add_middleware(
    SessionMemoryGuard,
    token_generator=token_gen,
    session_store=session_store,
    skip_paths={"/health", "/tokens/request", "/tokens/validate", "/tokens/revoke", "/tokens/delegate", "/tokens/delegations", "/agents", "/access/validate", "/security/efficacy", "/trust", "/audit"}
)

# Auth
ADMIN_KEY = os.getenv("TESSERA_ADMIN_KEY", "tessera-demo-key-change-in-production")
if _strict_prod_mode():
    if not os.getenv("TESSERA_SECRET_KEY"):
        raise RuntimeError("TESSERA_SECRET_KEY must be set in strict production mode")
    if ADMIN_KEY == "tessera-demo-key-change-in-production":
        raise RuntimeError("TESSERA_ADMIN_KEY must be set to a non-demo value in strict production mode")

def verify_admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing authorization")
    if authorization.replace("Bearer ", "") != ADMIN_KEY:
        raise HTTPException(403, "Invalid admin key")
    return True

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/health")
def health():
    """Health check"""
    agents = registry.list_agents()
    return {
        "status": "healthy",
        "service": "tessera-iam",
        "vestigia": VESTIGIA_AVAILABLE,
        "agents": len(agents)
    }

@app.get("/agents/list")
def list_agents():
    """List all agents with full identity records."""
    try:
        agents = registry.list_agents()
        agent_list = [
            {
                "agent_id": a.agent_id,
                "owner": a.owner,
                "tenant_id": a.tenant_id,
                "status": a.status,
                "allowed_tools": a.allowed_tools,
                "max_token_ttl": a.max_token_ttl,
                "risk_threshold": a.risk_threshold,
                "trust_score": a.trust_score,
                "metadata": a.metadata,
                "allowed_domains": getattr(a, "allowed_domains", []),
                "allowed_path_prefixes": getattr(a, "allowed_path_prefixes", []),
                "require_sandbox": bool(getattr(a, "require_sandbox", False)),
                "active_key_id": getattr(a, "active_key_id", None),
                "allowed_delegates": getattr(a, "allowed_delegates", []),
                "allowed_roles": getattr(a, "allowed_roles", []),
            } for a in agents
        ]
        return {"agents": agent_list, "total": len(agent_list)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/agents/{agent_id}")
def get_agent(agent_id: str):
    """Get a single agent's full identity record."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(404, f"Agent '{agent_id}' not found")
    return {
        "agent_id": agent.agent_id,
        "owner": agent.owner,
        "tenant_id": agent.tenant_id,
        "status": agent.status,
        "allowed_tools": agent.allowed_tools,
        "max_token_ttl": agent.max_token_ttl,
        "risk_threshold": agent.risk_threshold,
        "trust_score": agent.trust_score,
        "trust_dependencies": agent.trust_dependencies,
        "status_reason": agent.status_reason,
        "last_updated": agent.last_updated,
        "metadata": agent.metadata,
        "allowed_domains": getattr(agent, "allowed_domains", []),
        "allowed_path_prefixes": getattr(agent, "allowed_path_prefixes", []),
        "require_sandbox": bool(getattr(agent, "require_sandbox", False)),
        "active_key_id": getattr(agent, "active_key_id", None),
        "allowed_delegates": getattr(agent, "allowed_delegates", []),
        "allowed_roles": getattr(agent, "allowed_roles", []),
        "agent_keys": [
            {k: v for k, v in key.items() if k != "private_key"}
            for key in (agent.agent_keys or [])
        ],
    }


class AgentRegisterRequest(BaseModel):
    agent_id: str
    owner: str
    allowed_tools: list
    tenant_id: str = "default"
    max_token_ttl: int = 3600
    risk_threshold: int = 50
    metadata: Optional[dict] = None
    allowed_domains: Optional[list] = None
    allowed_path_prefixes: Optional[list] = None
    require_sandbox: bool = False
    public_key: Optional[str] = None
    key_id: Optional[str] = None
    issuer_signature: Optional[str] = None
    allowed_delegates: Optional[list] = None
    allowed_roles: Optional[list] = None


@app.post("/agents/register")
def register_agent(req: AgentRegisterRequest):
    """Register a new agent or update an existing one (idempotent)."""
    try:
        agent = registry.register_agent(
            agent_id=req.agent_id,
            owner=req.owner,
            allowed_tools=req.allowed_tools,
            tenant_id=req.tenant_id,
            max_token_ttl=req.max_token_ttl,
            risk_threshold=req.risk_threshold,
            metadata=req.metadata,
            allowed_domains=req.allowed_domains,
            allowed_path_prefixes=req.allowed_path_prefixes,
            require_sandbox=req.require_sandbox,
            public_key=req.public_key,
            key_id=req.key_id,
            issuer_signature=req.issuer_signature,
            allowed_delegates=req.allowed_delegates,
            allowed_roles=req.allowed_roles,
        )
        is_new = agent.last_updated == agent.last_updated  # always true, but check below
        existing_before = registry.get_agent(req.agent_id)

        # Log to Vestigia
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_issued(req.agent_id, "agent_registered", "registration")

        audit_logger.log_event(
            event_type="agent_registered",
            agent_id=req.agent_id,
            status="success",
            details={"owner": req.owner, "tools": req.allowed_tools},
        )

        keys = registry.list_agent_keys(req.agent_id) or {}
        active_key = None
        if keys.get("keys"):
            active_key = next((k for k in keys["keys"] if k.get("key_id") == keys.get("active_key_id")), None)
        response = {
            "agent_id": agent.agent_id,
            "owner": agent.owner,
            "status": agent.status,
            "allowed_tools": agent.allowed_tools,
            "risk_threshold": agent.risk_threshold,
            "trust_score": agent.trust_score,
            "tenant_id": agent.tenant_id,
            "allowed_domains": agent.allowed_domains,
            "allowed_path_prefixes": agent.allowed_path_prefixes,
            "require_sandbox": agent.require_sandbox,
            "allowed_delegates": agent.allowed_delegates,
            "allowed_roles": agent.allowed_roles,
            "agent_key_id": keys.get("active_key_id"),
            "agent_public_key": active_key.get("public_key") if active_key else None,
            "agent_key_issuer": active_key.get("issuer") if active_key else None,
            "agent_key_issuer_signature": active_key.get("issuer_signature") if active_key else None,
        }
        if os.getenv("TESSERA_RETURN_PRIVATE_KEYS", "true").lower() in ("1", "true", "yes"):
            try:
                raw_agent = registry.get_agent(req.agent_id)
                if raw_agent and raw_agent.agent_keys:
                    for k in raw_agent.agent_keys:
                        if k.get("key_id") == keys.get("active_key_id"):
                            if k.get("private_key"):
                                response["agent_private_key"] = k.get("private_key")
            except Exception:
                pass
        return response
    except Exception as e:
        raise HTTPException(500, str(e))


class AgentUpdateRequest(BaseModel):
    status: Optional[str] = None
    reason: Optional[str] = None
    allowed_tools: Optional[list] = None
    owner: Optional[str] = None
    risk_threshold: Optional[int] = None
    max_token_ttl: Optional[int] = None
    metadata: Optional[dict] = None
    allowed_domains: Optional[list] = None
    allowed_path_prefixes: Optional[list] = None
    require_sandbox: Optional[bool] = None
    allowed_delegates: Optional[list] = None
    allowed_roles: Optional[list] = None


class KeyRevokeRequest(BaseModel):
    key_id: str
    reason: Optional[str] = None


class SignActionRequest(BaseModel):
    action_payload: dict
    key_id: Optional[str] = None


@app.patch("/agents/{agent_id}")
def update_agent(agent_id: str, req: AgentUpdateRequest):
    """Update an existing agent's properties."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(404, f"Agent '{agent_id}' not found")

    if req.status is not None:
        registry.update_agent_status(agent_id, req.status, req.reason)
    if req.allowed_tools is not None:
        agent.allowed_tools = list(req.allowed_tools)
    if req.owner is not None:
        agent.owner = req.owner
    if req.risk_threshold is not None:
        agent.risk_threshold = req.risk_threshold
    if req.max_token_ttl is not None:
        agent.max_token_ttl = req.max_token_ttl
    if req.metadata is not None:
        agent.metadata = req.metadata
    if req.allowed_domains is not None:
        agent.allowed_domains = list(req.allowed_domains)
    if req.allowed_path_prefixes is not None:
        agent.allowed_path_prefixes = list(req.allowed_path_prefixes)
    if req.require_sandbox is not None:
        agent.require_sandbox = bool(req.require_sandbox)
    if req.allowed_delegates is not None:
        agent.allowed_delegates = list(req.allowed_delegates)
    if req.allowed_roles is not None:
        agent.allowed_roles = list(req.allowed_roles)

    agent.last_updated = datetime.now(UTC).isoformat()
    registry._save_registry()

    audit_logger.log_event(
        event_type="agent_updated",
        agent_id=agent_id,
        status="success",
        details={"fields_changed": [k for k, v in req.model_dump().items() if v is not None]},
    )

    return {"agent_id": agent_id, "status": agent.status, "updated": True}


@app.delete("/agents/{agent_id}")
def delete_agent(agent_id: str):
    """Remove an agent from the registry."""
    if not registry.delete_agent(agent_id):
        raise HTTPException(404, f"Agent '{agent_id}' not found")

    audit_logger.log_event(
        event_type="agent_deleted",
        agent_id=agent_id,
        status="success",
    )
    return {"agent_id": agent_id, "deleted": True}


class AuditPruneRequest(BaseModel):
    retention_days: int


@app.get("/audit/export")
def export_audit(
    limit: int = 500,
    since: Optional[str] = None,
    verify: bool = False,
    authorization: Optional[str] = Header(None),
):
    verify_admin(authorization)
    cutoff = _parse_iso(since) if since else None
    entries = []
    for entry in audit_logger.iter_events():
        ts = _parse_iso(entry.get("timestamp"))
        if cutoff and ts and ts < cutoff:
            continue
        entries.append(entry)
    if limit > 0:
        entries = entries[-limit:]
    response = {"count": len(entries), "entries": entries}
    if verify:
        response["integrity_valid"] = audit_logger.verify_chain()
    return response


@app.post("/audit/prune")
def prune_audit(req: AuditPruneRequest, authorization: Optional[str] = Header(None)):
    verify_admin(authorization)
    removed = audit_logger.apply_retention(int(req.retention_days))
    return {"removed": removed, "retention_days": req.retention_days}


@app.get("/agents/{agent_id}/keys")
def list_agent_keys(agent_id: str):
    keys = registry.list_agent_keys(agent_id)
    if not keys:
        raise HTTPException(404, f"Agent '{agent_id}' not found")
    return keys


@app.post("/agents/{agent_id}/keys/rotate")
def rotate_agent_key(agent_id: str):
    key_record = registry.rotate_agent_key(agent_id)
    if not key_record:
        raise HTTPException(404, f"Agent '{agent_id}' not found")
    response = {k: v for k, v in key_record.items() if k != "private_key"}
    if os.getenv("TESSERA_RETURN_PRIVATE_KEYS", "true").lower() in ("1", "true", "yes"):
        if key_record.get("private_key"):
            response["agent_private_key"] = key_record.get("private_key")
    audit_logger.log_event(
        event_type="agent_key_rotated",
        agent_id=agent_id,
        status="success",
        details={"key_id": key_record.get("key_id")},
    )
    return response


@app.post("/agents/{agent_id}/keys/revoke")
def revoke_agent_key(agent_id: str, req: KeyRevokeRequest):
    ok = registry.revoke_agent_key(agent_id, req.key_id, req.reason)
    if not ok:
        raise HTTPException(404, f"Agent '{agent_id}' or key not found")
    audit_logger.log_event(
        event_type="agent_key_revoked",
        agent_id=agent_id,
        status="success",
        details={"key_id": req.key_id, "reason": req.reason},
    )
    return {"agent_id": agent_id, "revoked": True, "key_id": req.key_id}


@app.get("/trust/root")
def get_trust_root():
    return registry.get_root_public_key()


@app.post("/agents/{agent_id}/sign")
def sign_action(agent_id: str, req: SignActionRequest):
    if os.getenv("TESSERA_ALLOW_SERVER_SIGNING", "true").lower() not in ("1", "true", "yes"):
        raise HTTPException(403, "Server-side signing disabled")
    result = registry.sign_action(agent_id, req.action_payload)
    if not result:
        raise HTTPException(400, "Unable to sign payload for agent")
    return result


# ============================================================================
# TOKENS
# ============================================================================

class TokenRequest(BaseModel):
    agent_id: str
    tool: str
    duration_minutes: int = 60
    session_id: Optional[str] = None
    memory_hash: Optional[str] = None
    memory_state: Optional[str] = None
    client_public_key: Optional[str] = None
    client_jwk: Optional[dict] = None
    dpop_thumbprint: Optional[str] = None
    role: Optional[str] = None

@app.post("/tokens/request")
def request_token(req: TokenRequest, request: Request, _: bool = Header(None)):
    """Generate token"""
    try:
        if not _tool_allowed(req.tool):
            raise HTTPException(403, "Tool not allowed")
        agent = registry.get_agent(req.agent_id)
        if not agent:
            raise HTTPException(400, f"Agent '{req.agent_id}' not found")
        if req.role and agent.allowed_roles and req.role not in agent.allowed_roles:
            raise HTTPException(403, "Role not allowed for agent")
        if not rate_limiter.allow(req.agent_id, limit=100, window_seconds=3600):
            raise HTTPException(429, "Rate limit exceeded")
        if METRICS_TOKEN_REQUESTS:
            METRICS_TOKEN_REQUESTS.inc()

        ttl_seconds = int(req.duration_minutes) * 60
        memory_hash = req.memory_hash
        if req.memory_state and not memory_hash:
            memory_hash = session_store.compute_memory_hash(req.memory_state.encode("utf-8"))
        if req.session_id and memory_hash:
            session_store.set_memory_hash(req.agent_id, req.session_id, memory_hash, ttl=_cap_memory_ttl(ttl_seconds))

        # Generate token
        token = token_gen.generate_token(
            agent_id=req.agent_id,
            tool=req.tool,
            custom_ttl=ttl_seconds,
            session_id=req.session_id,
            memory_hash=memory_hash,
            client_public_key=req.client_public_key,
            client_jwk=req.client_jwk,
            dpop_thumbprint=req.dpop_thumbprint,
            role=req.role,
        )
        
        # Check if token was generated
        if token is None:
            raise HTTPException(400, f"Agent '{req.agent_id}' not found or not authorized for '{req.tool}'")
        
        # Extract token data
        token_str = token.token if hasattr(token, 'token') else None
        jti = token.jti if hasattr(token, 'jti') else "unknown"
        expires = token.expires_at if hasattr(token, 'expires_at') else "unknown"
        
        if token_str is None:
            raise HTTPException(500, "Token generation returned None")
        
        # Log to Vestigia
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_issued(req.agent_id, req.tool, jti)

        audit_logger.log_event(
            event_type="token_issued",
            agent_id=req.agent_id,
            status="success",
            details={"tool": req.tool, "jti": jti}
        )
        _emit_integration_event(
            event_type="token_issued",
            agent_id=req.agent_id,
            status="success",
            tool=req.tool,
            evidence={
                "jti": jti,
                "agent_key_id": registry.get_agent(req.agent_id).active_key_id if registry.get_agent(req.agent_id) else None,
                "role": req.role,
            },
            session_id=req.session_id or _header_value(request, "X-Session-Id"),
            trace_id=_header_value(request, "X-Trace-Id", "X-Request-Id", "X-Correlation-Id"),
            correlation_id=jti,
        )

        return {
            "success": True,
            "token": token_str,
            "jti": jti,
            "expires_at": str(expires),
            "agent_key_id": agent.active_key_id if agent else None,
            "role": req.role,
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Token error: {e}")
        raise HTTPException(400, str(e))

class TokenValidate(BaseModel):
    token: str
    tool: str
    expected_htu: Optional[str] = None
    expected_htm: Optional[str] = None
    dpop_proof: Optional[str] = None
    target_url: Optional[str] = None
    file_path: Optional[str] = None
    sandbox_attested: Optional[bool] = None

class MemoryUpdate(BaseModel):
    agent_id: str
    session_id: str
    memory_state: Optional[str] = None
    memory_hash: Optional[str] = None
    ttl_seconds: int = 3600

@app.post("/tokens/validate")
def validate_token(req: TokenValidate, request: Request, dpop: Optional[str] = Header(None, alias="DPoP")):
    """Validate token"""
    try:
        if METRICS_TOKEN_VALIDATIONS:
            METRICS_TOKEN_VALIDATIONS.inc()

        dpop_proof = dpop or req.dpop_proof
        expected_htu = req.expected_htu or str(request.url)
        expected_htm = req.expected_htm or request.method

        # Validate using gatekeeper
        result = gatekeeper.validate_access(
            token=req.token,
            requested_tool=req.tool,
            dpop_proof=dpop_proof,
            expected_htu=expected_htu,
            expected_htm=expected_htm,
            target_url=req.target_url,
            file_path=req.file_path,
            sandbox_attested=req.sandbox_attested,
        )

        # DPoP replay detection (post-validation)
        if dpop_proof:
            try:
                proof_payload = jwt.decode(dpop_proof, options={"verify_signature": False})
                proof_jti = proof_payload.get("jti")
                if not dpop_replay_cache.check_and_store(proof_jti, ttl_seconds=60):
                    raise HTTPException(403, "DPoP proof replay detected")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(400, "Invalid DPoP proof")
        
        # Parse result
        SECURITY_EFFICACY["validations_total"] += 1
        session_id = None
        payload = None
        if isinstance(result, dict):
            valid = result.get('valid', False)
            agent_id = result.get('agent_id', 'unknown')
            reason = result.get('reason', 'unknown')
            session_id = result.get("session_id") or (result.get("payload") or {}).get("session_id")
            payload = result.get("payload")
        else:
            valid = result.decision == AccessDecision.ALLOW if hasattr(result, 'decision') else False
            agent_id = result.agent_id if hasattr(result, 'agent_id') else 'unknown'
            reason = result.reason if hasattr(result, 'reason') else 'unknown'
            if hasattr(result, "payload") and isinstance(result.payload, dict):
                session_id = result.payload.get("session_id")
                payload = result.payload
        if payload is None:
            try:
                payload = token_gen.validate_token(req.token) or {}
            except Exception:
                payload = {}
        jti = payload.get("jti") if isinstance(payload, dict) else None
        if valid:
            SECURITY_EFFICACY["allowed_total"] += 1
        else:
            SECURITY_EFFICACY["denied_total"] += 1
            key = str(reason or "unknown")
            by_reason = SECURITY_EFFICACY["denied_by_reason"]
            by_reason[key] = int(by_reason.get(key, 0)) + 1
        
        # Log to Vestigia
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_validated(agent_id, req.tool, valid, reason)

        audit_logger.log_event(
            event_type="token_validated",
            agent_id=agent_id,
            status="success" if valid else "deny",
            details={"tool": req.tool, "reason": reason}
        )
        _emit_integration_event(
            event_type="token_validated",
            agent_id=agent_id,
            status="success" if valid else "deny",
            tool=req.tool,
            reason=reason,
            session_id=session_id or _header_value(request, "X-Session-Id"),
            trace_id=_header_value(request, "X-Trace-Id", "X-Request-Id", "X-Correlation-Id"),
            correlation_id=jti,
        )
        
        return {
            "valid": valid,
            "agent_id": agent_id,
            "reason": reason
        }
    except Exception as e:
        print(f"❌ Validation error: {e}")
        if METRICS_ACCESS_DENIALS:
            METRICS_ACCESS_DENIALS.labels(reason="validation_error").inc()
        raise HTTPException(400, str(e))

@app.post("/sessions/memory/update")
def update_session_memory(
    req: MemoryUpdate,
    request: Request,
    authorization: Optional[str] = Header(None),
    dpop: Optional[str] = Header(None, alias="DPoP")
):
    """Update session memory hash for an agent."""
    try:
        if not rate_limiter.allow(req.agent_id, limit=100, window_seconds=3600):
            raise HTTPException(429, "Rate limit exceeded")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing bearer token")
        token = authorization.replace("Bearer ", "", 1).strip()

        gate_result = gatekeeper.validate_access(
            token=token,
            requested_tool="session_memory_update",
            dpop_proof=dpop,
            expected_htu=str(request.url),
            expected_htm=request.method
        )

        if gate_result.decision != AccessDecision.ALLOW:
            if METRICS_ACCESS_DENIALS:
                METRICS_ACCESS_DENIALS.labels(reason=gate_result.reason or "access_denied").inc()
            raise HTTPException(403, gate_result.reason or "Access denied")

        payload = gate_result.payload or {}
        if payload.get("sub") != req.agent_id:
            raise HTTPException(403, "Agent ID mismatch")
        if payload.get("session_id") and payload.get("session_id") != req.session_id:
            raise HTTPException(403, "Session ID mismatch")

        if not (req.memory_state or req.memory_hash):
            raise HTTPException(400, "memory_state or memory_hash required")
        memory_hash = req.memory_hash
        if req.memory_state and not memory_hash:
            memory_hash = session_store.compute_memory_hash(req.memory_state.encode("utf-8"))

        session_store.set_memory_hash(
            req.agent_id,
            req.session_id,
            memory_hash,
            ttl=_cap_memory_ttl(req.ttl_seconds)
        )

        audit_logger.log_event(
            event_type="session_memory_update",
            agent_id=req.agent_id,
            status="success",
            details={"session_id": req.session_id}
        )
        _emit_integration_event(
            event_type="session_memory_update",
            agent_id=req.agent_id,
            status="success",
            evidence={"session_id": req.session_id},
            session_id=req.session_id,
            trace_id=_header_value(request, "X-Trace-Id", "X-Request-Id", "X-Correlation-Id"),
        )

        return {"success": True, "memory_hash": memory_hash}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


class TokenRevoke(BaseModel):
    jti: Optional[str] = None
    token: Optional[str] = None
    reason: str = "Manual revocation"

@app.post("/tokens/revoke")
def revoke_token(req: TokenRevoke, _: bool = Header(None)):
    """Revoke token by JTI or raw token"""
    try:
        jti = req.jti
        if not jti and req.token:
            payload = token_gen.validate_token(req.token)
            if not payload:
                raise HTTPException(400, "Invalid token — cannot extract JTI")
            jti = payload.get("jti")
        if not jti:
            raise HTTPException(400, "Must provide jti or token")
        revocation.revoke(jti, reason=req.reason)

        if METRICS_TOKEN_REVOCATIONS:
            METRICS_TOKEN_REVOCATIONS.inc()
        
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_revoked("admin", jti, req.reason)

        audit_logger.log_event(
            event_type="token_revoked",
            agent_id="admin",
            status="success",
            details={"jti": jti, "reason": req.reason}
        )
        _emit_integration_event(
            event_type="token_revoked",
            agent_id="admin",
            status="success",
            evidence={"jti": jti, "reason": req.reason},
            session_id="admin",
            trace_id=jti,
            correlation_id=jti,
        )
        
        return {"success": True, "revoked": True, "jti": jti}
    except Exception as e:
        raise HTTPException(400, str(e))

class AccessValidate(BaseModel):
    token: str
    agent_id: str
    tool: str
    parameters: dict
    reasoning_chain: list
    original_goal: str
    context: Optional[dict] = None
    role: Optional[str] = None
    sandbox_attested: Optional[bool] = None
    action_signature: Optional[str] = None
    action_payload: Optional[dict] = None
    key_id: Optional[str] = None

@app.post("/access/validate")
def access_validate(req: AccessValidate, request: Request):
    """Validate access using Tessera + VerityFlux (if available)."""
    if not VERITYFLUX_AVAILABLE or not verityflux_bridge:
        raise HTTPException(503, "VerityFlux integration unavailable")

    if _denial_blocked(req.agent_id):
        return {
            "decision": "deny_policy",
            "tessera_decision": "deny_policy",
            "tessera_reason": "Circuit breaker: repeated denials",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Circuit breaker: repeated denials",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": None,
        }

    if not rate_limiter.allow(f"access:{req.agent_id}", limit=TESSERA_ACCESS_RATE_LIMIT, window_seconds=TESSERA_ACCESS_WINDOW_SECONDS):
        _record_denial(req.agent_id)
        return {
            "decision": "deny_policy",
            "tessera_decision": "deny_policy",
            "tessera_reason": "Access rate limit exceeded",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Access rate limit exceeded",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": None,
        }

    if not _tool_allowed(req.tool):
        _record_denial(req.agent_id)
        return {
            "decision": "deny_policy",
            "tessera_decision": "deny_policy",
            "tessera_reason": "Tool not allowed",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Tool not allowed",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": None,
        }

    schema_error = _validate_tool_params(req.tool, req.parameters or {})
    if schema_error:
        _record_denial(req.agent_id)
        return {
            "decision": "deny_policy",
            "tessera_decision": "deny_policy",
            "tessera_reason": schema_error,
            "verityflux_risk": 0.0,
            "verityflux_reason": schema_error,
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": None,
        }

    if TESSERA_REQUIRE_TRUSTED_CONTEXT:
        ctx = req.context or {}
        trust_level = (ctx.get("trust_level") or ctx.get("source_trust") or ctx.get("trust") or "").lower()
        if trust_level and trust_level not in TESSERA_TRUSTED_CONTEXT_LEVELS:
            _record_denial(req.agent_id)
            return {
                "decision": "deny_policy",
                "tessera_decision": "deny_policy",
                "tessera_reason": "Untrusted context",
                "verityflux_risk": 0.0,
                "verityflux_reason": "Untrusted context",
                "risk_breakdown": None,
                "agent_id": req.agent_id,
                "tool": req.tool,
                "signature_valid": False,
                "signature_key_id": None,
                "action_hash": None,
            }
    signature_result = None
    action_payload = req.action_payload or {
        "agent_id": req.agent_id,
        "tool": req.tool,
        "parameters": req.parameters,
        "reasoning_chain": req.reasoning_chain,
        "original_goal": req.original_goal,
        "context": req.context or {},
        "role": req.role,
    }
    action_hash = hashlib.sha256(
        json.dumps(action_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if req.action_signature:
        signature_result = registry.verify_action_signature(
            agent_id=req.agent_id,
            payload=action_payload,
            signature=req.action_signature,
            key_id=req.key_id,
        )
    elif os.getenv("TESSERA_REQUIRE_ACTION_SIGNATURE", "true").lower() in ("1", "true", "yes"):
        _record_denial(req.agent_id)
        return {
            "decision": "deny_identity",
            "tessera_decision": "deny_identity",
            "tessera_reason": "Missing action signature",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Missing action signature",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": action_hash,
        }

    if not action_replay_cache.check_and_store(action_hash, ttl_seconds=TESSERA_ACTION_REPLAY_TTL):
        _record_denial(req.agent_id)
        return {
            "decision": "deny_policy",
            "tessera_decision": "deny_policy",
            "tessera_reason": "Action replay detected",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Action replay detected",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": action_hash,
        }

    token_payload = token_gen.validate_token(req.token)
    if not token_payload:
        _record_denial(req.agent_id)
        return {
            "decision": "deny_identity",
            "tessera_decision": "deny_identity",
            "tessera_reason": "Invalid token",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Invalid token",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": action_hash,
        }

    token_role = token_payload.get("role")
    if req.role and token_role and req.role != token_role:
        _record_denial(req.agent_id)
        return {
            "decision": "deny_identity",
            "tessera_decision": "deny_identity",
            "tessera_reason": "Role mismatch",
            "verityflux_risk": 0.0,
            "verityflux_reason": "Role mismatch",
            "risk_breakdown": None,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "signature_valid": False,
            "signature_key_id": None,
            "action_hash": action_hash,
        }
    if not req.role and token_role:
        req.role = token_role

    agent = registry.get_agent(req.agent_id)
    if agent and agent.allowed_roles:
        effective_role = req.role or token_role
        if effective_role and effective_role not in agent.allowed_roles:
            _record_denial(req.agent_id)
            return {
                "decision": "deny_identity",
                "tessera_decision": "deny_identity",
                "tessera_reason": "Role not allowed",
                "verityflux_risk": 0.0,
                "verityflux_reason": "Role not allowed",
                "risk_breakdown": None,
                "agent_id": req.agent_id,
                "tool": req.tool,
                "signature_valid": False,
                "signature_key_id": None,
                "action_hash": action_hash,
            }
    result = verityflux_bridge.validate_action(
        token=req.token,
        agent_id=req.agent_id,
        tool_name=req.tool,
        parameters=req.parameters,
        reasoning_chain=req.reasoning_chain,
        original_goal=req.original_goal,
        context=req.context,
        sandbox_attested=req.sandbox_attested,
    )
    out = result.to_dict()
    out["signature_valid"] = signature_result.get("valid") if signature_result else None
    out["signature_key_id"] = signature_result.get("key_id") if signature_result else req.key_id
    out["action_hash"] = action_hash
    out["role"] = req.role or token_role
    context = req.context or {}
    if out.get("decision") not in ("allow", "approved", "permit", "success"):
        _record_denial(req.agent_id)
    audit_logger.log_event(
        event_type="action_validated",
        agent_id=req.agent_id,
        status=out.get("decision", "unknown"),
        details={
            "tool": req.tool,
            "role": out.get("role"),
            "signature_valid": out.get("signature_valid"),
            "action_hash": action_hash,
        },
    )
    _emit_integration_event(
        event_type="action_validated",
        agent_id=req.agent_id,
        status=out.get("decision", "unknown"),
        tool=req.tool,
        evidence={
            "action_hash": action_hash,
            "signature_valid": out["signature_valid"],
            "signature_key_id": out["signature_key_id"],
            "role": out.get("role"),
        },
        reason=out.get("tessera_reason"),
        session_id=context.get("session_id"),
        trace_id=context.get("trace_id") or _header_value(request, "X-Trace-Id", "X-Request-Id", "X-Correlation-Id"),
    )
    return out

class DelegateRequest(BaseModel):
    parent_token: str
    sub_agent_id: str
    requested_scopes: list

@app.post("/tokens/delegate")
def delegate_token(req: DelegateRequest):
    """Create a delegated token for a sub-agent with narrowed scopes."""
    try:
        # Validate parent token
        parent_payload = token_gen.validate_token(req.parent_token)
        if not parent_payload:
            raise HTTPException(401, "Invalid parent token")

        parent_id = parent_payload.get("sub")
        if parent_id:
            parent_agent = registry.get_agent(parent_id)
            if parent_agent and parent_agent.allowed_delegates:
                if req.sub_agent_id not in parent_agent.allowed_delegates:
                    raise HTTPException(403, "Delegation not allowed for target agent")
            if not rate_limiter.allow(f"delegate:{parent_id}", limit=30, window_seconds=3600):
                raise HTTPException(429, "Delegation rate limit exceeded")

        # Create delegation
        delegated = delegation_chain.create_delegated_token(
            parent_token=parent_payload,
            sub_agent_id=req.sub_agent_id,
            requested_scopes=set(req.requested_scopes),
        )

        if not delegated:
            raise HTTPException(
                403,
                "Delegation failed: scopes not subset of parent or max depth exceeded"
            )

        # Generate actual JWT for the sub-agent
        parent_tool = parent_payload.get("tool", "")
        effective_tool = parent_tool  # Use parent's tool for scope compatibility

        parent_cnf = parent_payload.get("cnf") or {}
        parent_jkt = parent_cnf.get("jkt")

        sub_token = token_gen.generate_token(
            agent_id=req.sub_agent_id,
            tool=effective_tool,
            custom_ttl=TESSERA_DELEGATION_TTL_SECONDS,
            session_id=parent_payload.get("session_id"),
            memory_hash=parent_payload.get("memory_hash"),
            delegation_chain=delegated.delegation_chain,
            parent_jti=delegated.parent_jti,
            delegation_depth=delegated.depth,
            dpop_thumbprint=parent_jkt,
        )

        if sub_token is None:
            raise HTTPException(400, f"Sub-agent '{req.sub_agent_id}' not found or unauthorized")

        audit_logger.log_event(
            event_type="delegation_created",
            agent_id=req.sub_agent_id,
            status="success",
            details={
                "parent_jti": delegated.parent_jti,
                "depth": delegated.depth,
                "effective_scopes": list(delegated.effective_scopes),
            }
        )
        _emit_integration_event(
            event_type="delegation_created",
            agent_id=req.sub_agent_id,
            status="success",
            evidence={
                "parent_jti": delegated.parent_jti,
                "depth": delegated.depth,
            },
            session_id=parent_payload.get("session_id") if isinstance(parent_payload, dict) else None,
            correlation_id=delegated.parent_jti,
        )

        return {
            "success": True,
            "token": sub_token.token,
            "jti": sub_token.jti,
            "delegation_depth": delegated.depth,
            "effective_scopes": list(delegated.effective_scopes),
            "parent_jti": delegated.parent_jti,
            "expires_at": str(sub_token.expires_at),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/tokens/delegations")
def list_delegations(limit: int = 100):
    """List active in-memory delegation records for live dashboard views."""
    rows = []
    for jti, delegated in delegation_chain._delegations.items():
        chain = delegated.delegation_chain if isinstance(delegated.delegation_chain, list) else []
        latest_link = chain[-1] if chain else {}
        rows.append({
            "jti": jti,
            "sub_agent_id": latest_link.get("delegated_to"),
            "agent_id": latest_link.get("agent_id"),
            "parent_jti": delegated.parent_jti,
            "depth": delegated.depth,
            "effective_scopes": list(delegated.effective_scopes),
            "delegation_chain": chain,
            "expires_at": None,
            "delegated_at": str(delegated.delegated_at),
        })
    rows.sort(key=lambda r: str(r.get("delegated_at", "")), reverse=True)
    return {"items": rows[: max(1, min(limit, 1000))], "total": len(rows)}

@app.get("/metrics")
def metrics():
    if not generate_latest:
        raise HTTPException(500, "Prometheus client not installed")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/security/efficacy")
def security_efficacy():
    total = int(SECURITY_EFFICACY["validations_total"])
    denied = int(SECURITY_EFFICACY["denied_total"])
    allowed = int(SECURITY_EFFICACY["allowed_total"])
    return {
        **SECURITY_EFFICACY,
        "allow_rate_pct": round((allowed / total) * 100.0, 2) if total else 0.0,
        "deny_rate_pct": round((denied / total) * 100.0, 2) if total else 0.0,
        "updated_at": datetime.now(UTC).isoformat(),
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🔐 TESSERA IAM API SERVER")
    print("=" * 70)
    print(f"   Vestigia: {'ENABLED' if VESTIGIA_AVAILABLE else 'DISABLED'}")
    api_port = int(os.getenv("TESSERA_PORT", "8001"))
    certfile = os.getenv("TESSERA_TLS_CERTFILE") or os.getenv("TLS_CERTFILE")
    keyfile = os.getenv("TESSERA_TLS_KEYFILE") or os.getenv("TLS_KEYFILE")
    scheme = "https" if certfile and keyfile else "http"
    print(f"   Listening: {scheme}://0.0.0.0:{api_port}")
    print("=" * 70)

    ssl_kwargs = {}
    if certfile and keyfile:
        ssl_kwargs = {"ssl_certfile": certfile, "ssl_keyfile": keyfile}

    uvicorn.run(app, host="0.0.0.0", port=api_port, log_level="info", **ssl_kwargs)

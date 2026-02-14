#!/usr/bin/env python3
"""
Tessera API - MINIMAL WORKING VERSION
Only uses methods that actually exist in Tessera

Save as: ~/ml-redteam/tessera/api_server.py
"""

import os
import sys
import json
from datetime import datetime, UTC
from urllib import request as urllib_request
from pathlib import Path

# Environment
if not os.getenv('TESSERA_SECRET_KEY'):
    os.environ['TESSERA_SECRET_KEY'] = '168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06'

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
from tessera.revocation import RevocationList
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

try:
    from integration.verityflux_bridge import TesseraVerityFluxBridge
    verityflux_bridge = TesseraVerityFluxBridge(gatekeeper)
    VERITYFLUX_AVAILABLE = True
except Exception as e:
    VERITYFLUX_AVAILABLE = False
    verityflux_bridge = None
    print(f"⚠️  VerityFlux bridge unavailable: {e}")

# ---------------------------------------------------------------------------
# Integration hooks (opt-in)
# ---------------------------------------------------------------------------

def _integration_enabled() -> bool:
    return os.getenv("MLRT_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes")


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
) -> None:
    if not _integration_enabled():
        return
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "tessera",
        "event_type": event_type,
        "actor": {"agent_id": agent_id},
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
rate_limiter = RateLimiter()

if Counter:
    METRICS_TOKEN_REQUESTS = Counter("tessera_token_requests_total", "Token requests")
    METRICS_TOKEN_VALIDATIONS = Counter("tessera_token_validations_total", "Token validations")
    METRICS_TOKEN_REVOCATIONS = Counter("tessera_token_revocations_total", "Token revocations")
    METRICS_ACCESS_DENIALS = Counter("tessera_access_denials_total", "Access denials", ["reason"])
    METRICS_REQUEST_DURATION = Histogram("tessera_request_duration_seconds", "Request duration", ["endpoint"])

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
    skip_paths={"/health", "/tokens/request", "/tokens/validate", "/tokens/revoke", "/agents/list"}
)

# Auth
ADMIN_KEY = "tessera-demo-key-change-in-production"

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
    """List all agents"""
    try:
        agents = registry.list_agents()
        return {
            "agents": [
                {
                    "agent_id": a.agent_id,
                    "allowed_tools": a.allowed_tools,
                    "owner": a.owner,
                    "status": a.status
                } for a in agents
            ]
        }
    except Exception as e:
        raise HTTPException(500, str(e))

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

@app.post("/tokens/request")
def request_token(req: TokenRequest, _: bool = Header(None)):
    """Generate token"""
    try:
        if not rate_limiter.allow(req.agent_id, limit=100, window_seconds=3600):
            raise HTTPException(429, "Rate limit exceeded")
        if METRICS_TOKEN_REQUESTS:
            METRICS_TOKEN_REQUESTS.inc()

        ttl_seconds = int(req.duration_minutes) * 60
        memory_hash = req.memory_hash
        if req.memory_state and not memory_hash:
            memory_hash = session_store.compute_memory_hash(req.memory_state.encode("utf-8"))
        if req.session_id and memory_hash:
            session_store.set_memory_hash(req.agent_id, req.session_id, memory_hash, ttl=ttl_seconds)

        # Generate token
        token = token_gen.generate_token(
            agent_id=req.agent_id,
            tool=req.tool,
            custom_ttl=ttl_seconds,
            session_id=req.session_id,
            memory_hash=memory_hash,
            client_public_key=req.client_public_key,
            client_jwk=req.client_jwk,
            dpop_thumbprint=req.dpop_thumbprint
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
            evidence={"jti": jti},
        )
        
        return {
            "success": True,
            "token": token_str,
            "jti": jti,
            "expires_at": str(expires)
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
            expected_htm=expected_htm
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
        if isinstance(result, dict):
            valid = result.get('valid', False)
            agent_id = result.get('agent_id', 'unknown')
            reason = result.get('reason', 'unknown')
        else:
            valid = result.decision.value == 'ALLOW' if hasattr(result, 'decision') else False
            agent_id = result.agent_id if hasattr(result, 'agent_id') else 'unknown'
            reason = result.reason if hasattr(result, 'reason') else 'unknown'
        
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
            ttl=req.ttl_seconds
        )

        audit_logger.log_event(
            event_type="session_memory_update",
            agent_id=req.agent_id,
            status="success",
            details={"session_id": req.session_id}
        )

        return {"success": True, "memory_hash": memory_hash}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


class TokenRevoke(BaseModel):
    jti: str
    reason: str = "Manual revocation"

@app.post("/tokens/revoke")
def revoke_token(req: TokenRevoke, _: bool = Header(None)):
    """Revoke token"""
    try:
        revocation.revoke(req.jti, reason=req.reason)

        if METRICS_TOKEN_REVOCATIONS:
            METRICS_TOKEN_REVOCATIONS.inc()
        
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_revoked("admin", req.jti, req.reason)

        audit_logger.log_event(
            event_type="token_revoked",
            agent_id="admin",
            status="success",
            details={"jti": req.jti, "reason": req.reason}
        )
        _emit_integration_event(
            event_type="token_revoked",
            agent_id="admin",
            status="success",
            evidence={"jti": req.jti, "reason": req.reason},
        )
        
        return {"success": True, "jti": req.jti}
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

@app.post("/access/validate")
def access_validate(req: AccessValidate):
    """Validate access using Tessera + VerityFlux (if available)."""
    if not VERITYFLUX_AVAILABLE or not verityflux_bridge:
        raise HTTPException(503, "VerityFlux integration unavailable")
    result = verityflux_bridge.validate_action(
        token=req.token,
        agent_id=req.agent_id,
        tool_name=req.tool,
        parameters=req.parameters,
        reasoning_chain=req.reasoning_chain,
        original_goal=req.original_goal,
        context=req.context
    )
    return result.to_dict()

@app.get("/metrics")
def metrics():
    if not generate_latest:
        raise HTTPException(500, "Prometheus client not installed")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🔐 TESSERA IAM API SERVER")
    print("=" * 70)
    print(f"   Vestigia: {'ENABLED' if VESTIGIA_AVAILABLE else 'DISABLED'}")
    api_port = int(os.getenv("TESSERA_PORT", "8001"))
    print(f"   Listening: http://0.0.0.0:{api_port}")
    print("=" * 70)
    
    uvicorn.run(app, host="0.0.0.0", port=api_port, log_level="info")

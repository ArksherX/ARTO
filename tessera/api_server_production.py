#!/usr/bin/env python3
"""
Tessera API - Production Server
PostgreSQL registry + Redis revocation + rate limiting + Prometheus metrics.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional
import uvicorn

sys.path.insert(0, str(Path(__file__).parent))

from tessera.token_generator import TokenGenerator
from tessera.agent_keys import verify_payload
from tessera.gatekeeper import Gatekeeper, AccessDecision
from tessera.session_store import SessionStateStore
from tessera.audit_logger import AuditChainLogger
from tessera.dpop_replay_cache import DPoPReplayCache
from tessera.rate_limiter import RateLimiter
from tessera.db_persistence import ProductionPersistence
from tessera.sso import OIDCValidator, LDAPAuthenticator, saml_from_env
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    Counter = Histogram = generate_latest = CONTENT_TYPE_LATEST = None

try:
    from integration.verityflux_bridge import TesseraVerityFluxBridge
    VERITYFLUX_AVAILABLE = True
except Exception:
    VERITYFLUX_AVAILABLE = False
    TesseraVerityFluxBridge = None


class ProductionRegistryAdapter:
    """Adapter to provide registry interface for TokenGenerator."""

    def __init__(self, persistence: ProductionPersistence):
        self.persistence = persistence

    def get_agent(self, agent_id: str):
        agent = self.persistence.get_agent(agent_id)
        if not agent:
            return None
        # Provide attributes used by TokenGenerator
        class AgentObj:
            pass
        obj = AgentObj()
        for k, v in agent.items():
            setattr(obj, k, v)
        return obj

    def list_agents(self, status: Optional[str] = None):
        return self.persistence.list_agents(status=status)


def _require_tenant(request: Request) -> str:
    tenant_id = request.headers.get("X-Tenant-ID")
    if not tenant_id:
        raise HTTPException(400, "X-Tenant-ID header required")
    return tenant_id


app = FastAPI(title="Tessera IAM (Production)", version="2.1")

registry_adapter = ProductionRegistryAdapter(ProductionPersistence())
token_gen = TokenGenerator(registry_adapter)
gatekeeper = Gatekeeper(token_gen, revocation_list=registry_adapter.persistence, registry=None)
session_store = SessionStateStore()
audit_logger = AuditChainLogger()
dpop_replay_cache = DPoPReplayCache()
rate_limiter = RateLimiter()

verityflux_bridge = TesseraVerityFluxBridge(gatekeeper) if VERITYFLUX_AVAILABLE else None

if Counter:
    METRICS_TOKEN_REQUESTS = Counter("tessera_token_requests_total", "Token requests")
    METRICS_TOKEN_VALIDATIONS = Counter("tessera_token_validations_total", "Token validations")
    METRICS_TOKEN_REVOCATIONS = Counter("tessera_token_revocations_total", "Token revocations")
    METRICS_ACCESS_DENIALS = Counter("tessera_access_denials_total", "Access denials", ["reason"])
    METRICS_REQUEST_DURATION = Histogram("tessera_request_duration_seconds", "Request duration", ["endpoint"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SSOMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.enabled = os.getenv("TESSERA_SSO_ENABLED", "false").lower() in ("1", "true", "yes")
        self.mode = os.getenv("TESSERA_SSO_MODE", "oidc")
        # Only enforce SSO on admin endpoints + metrics
        self.protected_paths = {"/tokens/revoke", "/access/validate", "/metrics", "/agents/register"}
        self.role_claim = os.getenv("TESSERA_SSO_ROLE_CLAIM", "roles")
        self.tenant_claim = os.getenv("TESSERA_SSO_TENANT_CLAIM", "tenant_id")
        self.admin_roles = set(r.strip() for r in os.getenv("TESSERA_SSO_ADMIN_ROLES", "admin,security").split(","))
        self.admin_users = set(r.strip() for r in os.getenv("TESSERA_SSO_ADMIN_USERS", "").split(",") if r.strip())
        self.endpoint_roles = self._load_rbac_policy()
        self.oidc = None
        self.ldap = None
        self.saml = None
        if self.enabled:
            if self.mode == "oidc":
                self.oidc = OIDCValidator(
                    os.getenv("OIDC_ISSUER", ""),
                    os.getenv("OIDC_AUDIENCE", ""),
                    os.getenv("OIDC_JWKS_URL", "")
                )
            elif self.mode == "ldap":
                self.ldap = LDAPAuthenticator(
                    os.getenv("LDAP_SERVER_URI", ""),
                    os.getenv("LDAP_BASE_DN", "")
                )
            elif self.mode == "saml":
                settings_path = os.getenv("SAML_SETTINGS_PATH", "")
                if settings_path and os.path.exists(settings_path):
                    self.saml = saml_from_env()

    async def dispatch(self, request: Request, call_next):
        if not self.enabled or request.url.path not in self.protected_paths:
            return await call_next(request)

        try:
            if self.mode == "oidc" and self.oidc:
                auth = request.headers.get("Authorization")
                claims = self.oidc.validate_bearer(auth)
                roles = claims.get(self.role_claim, [])
                if isinstance(roles, str):
                    roles = [roles]
                required = self._required_roles(request)
                if not set(roles).intersection(required):
                    raise HTTPException(403, "SSO role not authorized")
                tenant_header = request.headers.get("X-Tenant-ID")
                tenant_claim = claims.get(self.tenant_claim)
                if tenant_header and tenant_claim and tenant_header != tenant_claim:
                    raise HTTPException(403, "Tenant mismatch")
            elif self.mode == "ldap" and self.ldap:
                auth = request.headers.get("Authorization", "")
                if not auth.startswith("Basic "):
                    raise HTTPException(401, "Missing basic auth")
                import base64
                decoded = base64.b64decode(auth.replace("Basic ", "", 1)).decode("utf-8")
                username, password = decoded.split(":", 1)
                if not self.ldap.authenticate(username, password):
                    raise HTTPException(403, "LDAP authentication failed")
                if self.admin_users:
                    required_users = self.admin_users
                    if request.url.path in self.endpoint_roles and self.endpoint_roles[request.url.path] == {"admin"}:
                        required_users = self.admin_users
                    if username not in required_users:
                        raise HTTPException(403, "LDAP user not authorized")
            elif self.mode == "saml" and self.saml:
                form = await request.form()
                request_data = {
                    "https": "on",
                    "http_host": request.headers.get("host", ""),
                    "server_port": "443",
                    "script_name": request.url.path,
                    "get_data": {},
                    "post_data": {"SAMLResponse": form.get("SAMLResponse"), "RelayState": form.get("RelayState")}
                }
                result = self.saml.validate_response(request_data)
                roles = result.get("attributes", {}).get(self.role_claim, [])
                if isinstance(roles, str):
                    roles = [roles]
                required = self._required_roles(request)
                if not set(roles).intersection(required):
                    raise HTTPException(403, "SAML role not authorized")
                tenant_header = request.headers.get("X-Tenant-ID")
                attrs = result.get("attributes", {})
                tenant_claim = attrs.get(self.tenant_claim)
                if isinstance(tenant_claim, list):
                    tenant_claim = tenant_claim[0] if tenant_claim else None
                if tenant_header and tenant_claim and tenant_header != tenant_claim:
                    raise HTTPException(403, "Tenant mismatch")
            else:
                raise HTTPException(503, "SSO not configured")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(401, f"SSO validation failed: {e}")

        return await call_next(request)

    def _load_rbac_policy(self):
        policy = {
            "GET": {
                "/metrics": {"ops", "security", "admin"}
            },
            "POST": {
                "/tokens/revoke": {"security", "admin"},
                "/access/validate": {"security", "admin"},
                "/agents/register": {"admin"}
            }
        }
        policy_path = os.getenv("TESSERA_RBAC_POLICY_PATH")
        if policy_path and os.path.exists(policy_path):
            try:
                import json
                with open(policy_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {m: {p: set(r) for p, r in data.get(m, {}).items()} for m in data}
            except Exception:
                pass
        return policy

    def _required_roles(self, request: Request):
        method = request.method.upper()
        path = request.url.path
        method_policy = self.endpoint_roles.get(method, {})
        if path in method_policy:
            return method_policy[path]
        return self.admin_roles


app.add_middleware(SSOMiddleware)


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
def request_token(req: TokenRequest, request: Request):
    tenant_id = _require_tenant(request)
    agent = registry_adapter.persistence.get_agent(req.agent_id)
    if not agent or agent.get("tenant_id") != tenant_id:
        raise HTTPException(403, "Agent not in tenant")
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
    if not token:
        raise HTTPException(400, "Token generation failed")

    registry_adapter.persistence.log_audit(
        event_type="token_issued",
        agent_id=req.agent_id,
        details=f"tool={req.tool} jti={token.jti}",
        status="success"
    )
    audit_logger.log_event("token_issued", req.agent_id, "success", {"tool": req.tool, "jti": token.jti})

    return {"success": True, "token": token.token, "jti": token.jti, "expires_at": str(token.expires_at)}


class TokenValidate(BaseModel):
    token: str
    tool: str
    expected_htu: Optional[str] = None
    expected_htm: Optional[str] = None
    dpop_proof: Optional[str] = None


@app.post("/tokens/validate")
def validate_token(req: TokenValidate, request: Request, dpop: Optional[str] = Header(None, alias="DPoP")):
    tenant_id = _require_tenant(request)
    if METRICS_TOKEN_VALIDATIONS:
        METRICS_TOKEN_VALIDATIONS.inc()
    dpop_proof = dpop or req.dpop_proof
    expected_htu = req.expected_htu or str(request.url)
    expected_htm = req.expected_htm or request.method

    result = gatekeeper.validate_access(
        token=req.token,
        requested_tool=req.tool,
        dpop_proof=dpop_proof,
        expected_htu=expected_htu,
        expected_htm=expected_htm
    )
    if result.payload and result.payload.get("tenant_id") != tenant_id:
        raise HTTPException(403, "Tenant mismatch")

    if dpop_proof:
        import jwt as pyjwt
        proof_payload = pyjwt.decode(dpop_proof, options={"verify_signature": False})
        if not dpop_replay_cache.check_and_store(proof_payload.get("jti"), ttl_seconds=60):
            raise HTTPException(403, "DPoP proof replay detected")

    valid = result.decision == AccessDecision.ALLOW
    if not valid and METRICS_ACCESS_DENIALS:
        METRICS_ACCESS_DENIALS.labels(reason=result.reason or "deny").inc()

    registry_adapter.persistence.log_audit(
        event_type="token_validated",
        agent_id=result.agent_id or "unknown",
        details=f"tool={req.tool} valid={valid}",
        status="success" if valid else "deny"
    )
    audit_logger.log_event("token_validated", result.agent_id or "unknown", "success" if valid else "deny", {"tool": req.tool})
    return {"valid": valid, "agent_id": result.agent_id, "reason": result.reason}


class TokenRevoke(BaseModel):
    jti: str
    reason: str = "Manual revocation"


@app.post("/tokens/revoke")
def revoke_token(req: TokenRevoke):
    registry_adapter.persistence.revoke_token(req.jti, reason=req.reason, ttl=3600)
    if METRICS_TOKEN_REVOCATIONS:
        METRICS_TOKEN_REVOCATIONS.inc()
    return {"success": True, "jti": req.jti}


class AgentRegister(BaseModel):
    agent_id: str
    owner: str
    tenant_id: str
    allowed_tools: list
    max_token_ttl: int = 3600
    risk_threshold: int = 50
    status: str = "active"


@app.post("/agents/register")
def register_agent(req: AgentRegister, request: Request):
    tenant_id = _require_tenant(request)
    if req.tenant_id != tenant_id:
        raise HTTPException(403, "Tenant mismatch")
    registry_adapter.persistence.create_agent(
        agent_id=req.agent_id,
        owner=req.owner,
        tenant_id=tenant_id,
        allowed_tools=req.allowed_tools,
        max_token_ttl=req.max_token_ttl,
        risk_threshold=req.risk_threshold,
        status=req.status
    )
    return {"status": "success", "agent_id": req.agent_id}


class MemoryUpdate(BaseModel):
    agent_id: str
    session_id: str
    memory_state: Optional[str] = None
    memory_hash: Optional[str] = None
    ttl_seconds: int = 3600


@app.post("/sessions/memory/update")
def update_session_memory(
    req: MemoryUpdate,
    request: Request,
    authorization: Optional[str] = Header(None),
    dpop: Optional[str] = Header(None, alias="DPoP")
):
    tenant_id = _require_tenant(request)
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
        raise HTTPException(403, gate_result.reason or "Access denied")
    if gate_result.payload and gate_result.payload.get("sub") != req.agent_id:
        raise HTTPException(403, "Agent ID mismatch")
    if gate_result.payload and gate_result.payload.get("tenant_id") != tenant_id:
        raise HTTPException(403, "Tenant mismatch")

    if not (req.memory_state or req.memory_hash):
        raise HTTPException(400, "memory_state or memory_hash required")
    memory_hash = req.memory_hash
    if req.memory_state and not memory_hash:
        memory_hash = session_store.compute_memory_hash(req.memory_state.encode("utf-8"))
    session_store.set_memory_hash(req.agent_id, req.session_id, memory_hash, ttl=req.ttl_seconds)
    return {"success": True, "memory_hash": memory_hash}


class AccessValidate(BaseModel):
    token: str
    agent_id: str
    tool: str
    parameters: dict
    reasoning_chain: list
    original_goal: str
    context: Optional[dict] = None
    sandbox_attested: Optional[bool] = None
    action_signature: Optional[str] = None
    action_payload: Optional[dict] = None
    key_id: Optional[str] = None


@app.post("/access/validate")
def access_validate(req: AccessValidate, request: Request):
    tenant_id = _require_tenant(request)
    if not verityflux_bridge:
        raise HTTPException(503, "VerityFlux integration unavailable")
    action_payload = req.action_payload or {
        "agent_id": req.agent_id,
        "tool": req.tool,
        "parameters": req.parameters,
        "reasoning_chain": req.reasoning_chain,
        "original_goal": req.original_goal,
        "context": req.context or {},
    }
    action_hash = hashlib.sha256(
        json.dumps(action_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    signature_valid = None
    if req.action_signature:
        agent_record = registry_adapter.persistence.get_agent(req.agent_id) or {}
        public_key = agent_record.get("public_key") or agent_record.get("agent_public_key")
        if public_key:
            signature_valid = verify_payload(public_key, action_payload, req.action_signature)
    if os.getenv("TESSERA_REQUIRE_ACTION_SIGNATURE", "true").lower() in ("1", "true", "yes"):
        if not req.action_signature:
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
                "signature_key_id": req.key_id,
                "action_hash": action_hash,
            }
        if signature_valid is False:
            return {
                "decision": "deny_identity",
                "tessera_decision": "deny_identity",
                "tessera_reason": "Invalid action signature",
                "verityflux_risk": 0.0,
                "verityflux_reason": "Invalid action signature",
                "risk_breakdown": None,
                "agent_id": req.agent_id,
                "tool": req.tool,
                "signature_valid": False,
                "signature_key_id": req.key_id,
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
    if result.tessera_result.payload and result.tessera_result.payload.get("tenant_id") != tenant_id:
        raise HTTPException(403, "Tenant mismatch")
    out = result.to_dict()
    out["signature_valid"] = signature_valid
    out["signature_key_id"] = req.key_id
    out["action_hash"] = action_hash
    return out


@app.get("/health")
def health():
    return {"status": "healthy", "service": "tessera-iam", "verityflux": VERITYFLUX_AVAILABLE}


@app.get("/metrics")
def metrics():
    if not generate_latest:
        raise HTTPException(500, "Prometheus client not installed")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    port = int(os.getenv("PORT", os.getenv("TESSERA_PORT", "8000")))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

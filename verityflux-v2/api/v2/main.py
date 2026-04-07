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
import hashlib
import hmac
import base64
import secrets
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from pathlib import Path as FSPath
from urllib.parse import urlparse

# FastAPI
from fastapi import (
    FastAPI, HTTPException, Depends, Security, Query, Path, Body,
    BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Response
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from urllib import request as urllib_request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, EmailStr, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verityflux.api")

# Core scanner (v2)
from core.scanner import VerityFluxScanner
from core.types import ScanConfig, RiskLevel
from core.skill_security import SkillSecurityAssessor
from core.protocol_integrity import ProtocolIntegrityAnalyzer
from cognitive_firewall.firewall import reload_all_policies

# In-memory scan state (demo-safe; replace with DB/queue in production)
SCAN_STORE: Dict[str, Dict[str, Any]] = {}
SKILL_ASSESSMENT_STORE: Dict[str, Dict[str, Any]] = {}
# In-memory SOC agent inventory (demo-safe; replace with DB in production)
AGENT_STORE: Dict[str, Dict[str, Any]] = {}
# In-memory HITL approval queue (demo-safe; replace with persistent DB in production)
APPROVAL_STORE: Dict[str, Dict[str, Any]] = {}
# Runtime telemetry stores (in-memory, demo-safe; replace with DB in production)
RATIONALE_LOG: List[Dict[str, Any]] = []
MCP_RUGPULL_LOG: List[Dict[str, Any]] = []
MCP_SCHEMA_LOG: List[Dict[str, Any]] = []
MCP_PROTOCOL_LOG: List[Dict[str, Any]] = []
ENFORCEMENT_LOG: List[Dict[str, Any]] = []
MCP_IDENTITY_REPLAY_CACHE: Dict[str, int] = {}
MCP_IDENTITY_STATS: Dict[str, int] = {
    "issued": 0,
    "validated": 0,
    "rejected_expired": 0,
    "rejected_binding": 0,
    "rejected_replay": 0,
    "rejected_invalid": 0,
}

ENFORCEMENT_MODE = os.getenv("VERITYFLUX_ENFORCEMENT_MODE", "enforce").strip().lower()
REQUIRE_SANDBOX_FOR_EXEC = os.getenv("VERITYFLUX_REQUIRE_SANDBOX_FOR_EXEC", "false").lower() in ("1", "true", "yes")
_egress_allowlist_env = os.getenv("VERITYFLUX_EGRESS_ALLOWLIST", "")
EGRESS_ALLOWLIST = {d.strip().lower() for d in _egress_allowlist_env.split(",") if d.strip()}
_path_allowlist_env = os.getenv("VERITYFLUX_PATH_ALLOWLIST", "")
PATH_ALLOWLIST = [p.strip() for p in _path_allowlist_env.split(",") if p.strip()]


def _append_capped(store: List[Dict[str, Any]], entry: Dict[str, Any], max_items: int = 1000) -> None:
    store.append(entry)
    if len(store) > max_items:
        del store[: len(store) - max_items]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("utf-8"))


def _mcp_secret() -> bytes:
    raw = os.getenv("VERITYFLUX_MCP_TOOL_SECRET", "")
    if raw:
        return raw.encode("utf-8")
    strict_prod = os.getenv("SUITE_STRICT_MODE", "false").lower() in ("1", "true", "yes") and (
        os.getenv("MLRT_MODE", "").lower() == "prod" or os.getenv("MODE", "").lower() == "prod"
    )
    if strict_prod:
        raise RuntimeError("VERITYFLUX_MCP_TOOL_SECRET must be set in strict production mode")
    # Dev-safe stable secret for local usage
    return b"verityflux-mcp-dev-secret-change-in-production"


def _mcp_sign(payload: Dict[str, Any]) -> str:
    body = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(_mcp_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _mcp_verify(
    token: str,
    *,
    expected_agent_id: str,
    expected_tool_name: str,
    expected_session_id: Optional[str],
    expected_audience: str = "verityflux-api",
) -> Dict[str, Any]:
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        MCP_IDENTITY_STATS["rejected_invalid"] += 1
        return {"valid": False, "reason": "Malformed MCP token"}

    want = hmac.new(_mcp_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, want):
        MCP_IDENTITY_STATS["rejected_invalid"] += 1
        return {"valid": False, "reason": "MCP token signature invalid"}

    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception:
        MCP_IDENTITY_STATS["rejected_invalid"] += 1
        return {"valid": False, "reason": "MCP token payload invalid"}

    now = int(datetime.now(UTC).timestamp())
    exp = int(payload.get("exp", 0))
    if exp <= now:
        MCP_IDENTITY_STATS["rejected_expired"] += 1
        return {"valid": False, "reason": "MCP token expired"}

    nonce = str(payload.get("nonce", ""))
    replay_key = f"{payload.get('jti', '')}:{nonce}"
    if replay_key in MCP_IDENTITY_REPLAY_CACHE:
        MCP_IDENTITY_STATS["rejected_replay"] += 1
        return {"valid": False, "reason": "MCP token replay detected"}
    MCP_IDENTITY_REPLAY_CACHE[replay_key] = exp
    # Opportunistic cleanup
    for k, expiry in list(MCP_IDENTITY_REPLAY_CACHE.items()):
        if expiry <= now:
            MCP_IDENTITY_REPLAY_CACHE.pop(k, None)

    if payload.get("aud") != expected_audience:
        MCP_IDENTITY_STATS["rejected_binding"] += 1
        return {"valid": False, "reason": "MCP token audience mismatch"}
    if payload.get("agent_id") != expected_agent_id:
        MCP_IDENTITY_STATS["rejected_binding"] += 1
        return {"valid": False, "reason": "MCP token agent binding mismatch"}
    if payload.get("tool_name") != expected_tool_name:
        MCP_IDENTITY_STATS["rejected_binding"] += 1
        return {"valid": False, "reason": "MCP token tool binding mismatch"}
    if expected_session_id and payload.get("session_id") != expected_session_id:
        MCP_IDENTITY_STATS["rejected_binding"] += 1
        return {"valid": False, "reason": "MCP token session binding mismatch"}

    MCP_IDENTITY_STATS["validated"] += 1
    return {"valid": True, "payload": payload}


ATTESTATION_ENABLED = os.getenv("VERITYFLUX_ATTESTATION_ENABLED", "true").lower() in ("1", "true", "yes")
ATTESTATION_INCLUDE_PUBLIC_KEY = os.getenv("VERITYFLUX_ATTESTATION_INCLUDE_PUBLIC_KEY", "false").lower() in ("1", "true", "yes")
ATTESTATION_INCLUDE_PAYLOAD = os.getenv("VERITYFLUX_ATTESTATION_INCLUDE_PAYLOAD", "true").lower() in ("1", "true", "yes")
_ATTESTATION_KEY_CACHE: Optional[Dict[str, Any]] = None


def _attestation_key_path() -> FSPath:
    raw = os.getenv("VERITYFLUX_ATTESTATION_KEY_PATH")
    if raw:
        p = FSPath(raw)
        if not p.is_absolute():
            p = BASE_DIR / raw
        return p
    return BASE_DIR / "data" / "attestation_key.json"


def _load_attestation_key() -> Dict[str, Any]:
    global _ATTESTATION_KEY_CACHE
    if _ATTESTATION_KEY_CACHE:
        return _ATTESTATION_KEY_CACHE
    path = _attestation_key_path()
    if path.exists():
        _ATTESTATION_KEY_CACHE = json.loads(path.read_text(encoding="utf-8"))
        return _ATTESTATION_KEY_CACHE
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    key_id = hashlib.sha256(public_pem.encode("utf-8")).hexdigest()
    record = {
        "key_id": key_id,
        "private_key": private_pem,
        "public_key": public_pem,
        "created_at": datetime.now(UTC).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    _ATTESTATION_KEY_CACHE = record
    return record


def _sign_attestation(payload: Dict[str, Any]) -> Dict[str, Any]:
    key = _load_attestation_key()
    private_key = serialization.load_pem_private_key(
        key["private_key"].encode("utf-8"), password=None
    )
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(body)
    return {
        "signature": _b64url(signature),
        "key_id": key["key_id"],
        "public_key": key["public_key"],
        "hash": hashlib.sha256(body).hexdigest(),
    }


def _extract_candidate_urls(arguments: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    if not isinstance(arguments, dict):
        return urls
    for _, v in arguments.items():
        if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
            urls.append(v)
    return urls


def _extract_candidate_paths(arguments: Dict[str, Any]) -> List[str]:
    paths: List[str] = []
    if not isinstance(arguments, dict):
        return paths
    for key, v in arguments.items():
        if not isinstance(v, str):
            continue
        lk = str(key).lower()
        if "path" in lk or "file" in lk:
            paths.append(v)
    return paths


def _runtime_containment_checks(tool_name: str, arguments: Dict[str, Any], sandbox_attested: bool = False) -> Dict[str, Any]:
    violations: List[str] = []

    # Sandbox requirement for execution-capable tools (opt-in by env)
    if REQUIRE_SANDBOX_FOR_EXEC:
        t = (tool_name or "").lower()
        if any(x in t for x in ("execute", "shell", "command", "python", "code")) and not sandbox_attested:
            violations.append("Sandbox attestation required for execution-capable tool")

    # Egress domain allowlist (opt-in by env)
    if EGRESS_ALLOWLIST:
        for u in _extract_candidate_urls(arguments):
            host = (urlparse(u).hostname or "").lower()
            if host and host not in EGRESS_ALLOWLIST:
                violations.append(f"Egress host '{host}' not in allowlist")

    # File path allowlist (opt-in by env)
    if PATH_ALLOWLIST:
        for p in _extract_candidate_paths(arguments):
            if not any(str(p).startswith(prefix) for prefix in PATH_ALLOWLIST):
                violations.append(f"Path '{p}' outside containment allowlist")

    return {
        "valid": len(violations) == 0,
        "violations": violations,
    }

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


def _scan_store_path() -> FSPath:
    env_path = os.getenv("VERITYFLUX_SCAN_STORE_PATH")
    if env_path:
        return FSPath(env_path)
    return BASE_DIR / "data" / "scan_results.json"


def _skill_assessment_store_path() -> FSPath:
    env_path = os.getenv("VERITYFLUX_SKILL_ASSESSMENT_STORE_PATH")
    if env_path:
        return FSPath(env_path)
    return BASE_DIR / "data" / "skill_assessments.json"


def _load_scan_store() -> None:
    path = _scan_store_path()
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        scans = payload.get("scans", {})
        if not isinstance(scans, dict):
            return
        SCAN_STORE.clear()
        for scan_id, row in scans.items():
            if not isinstance(row, dict):
                continue
            record = dict(row)
            for dt_key in ("started_at", "completed_at"):
                val = record.get(dt_key)
                if isinstance(val, str):
                    try:
                        record[dt_key] = datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except Exception:
                        record[dt_key] = None
            # Parse result: may be dict, Python repr string, or ScanResultResponse
            raw_result = record.get("result")
            if isinstance(raw_result, str):
                try:
                    import ast
                    record["result"] = ast.literal_eval(raw_result)
                except Exception:
                    try:
                        record["result"] = json.loads(raw_result)
                    except Exception:
                        record["result"] = None
            SCAN_STORE[str(scan_id)] = record
        logger.info("Loaded %d scans from disk", len(SCAN_STORE))
    except Exception as exc:
        logger.warning("Failed to load scan store: %s", exc)


def _save_scan_store() -> None:
    path = _scan_store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        serialisable = {}
        for scan_id, scan in SCAN_STORE.items():
            row = {}
            for k, v in scan.items():
                if k == "result" and v is not None:
                    # ScanResultResponse -> dict
                    if hasattr(v, "model_dump"):
                        row[k] = v.model_dump(mode="json")
                    elif hasattr(v, "dict"):
                        row[k] = v.dict()
                    elif isinstance(v, dict):
                        row[k] = v
                    else:
                        row[k] = None
                else:
                    row[k] = v
            serialisable[scan_id] = row
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"scans": serialisable}, f, indent=2, default=_json_default)
    except Exception as exc:
        logger.warning("Failed to save scan store: %s", exc)


def _load_skill_assessment_store() -> None:
    path = _skill_assessment_store_path()
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        assessments = payload.get("assessments", {})
        if not isinstance(assessments, dict):
            return
        SKILL_ASSESSMENT_STORE.clear()
        for assessment_id, row in assessments.items():
            if isinstance(row, dict):
                SKILL_ASSESSMENT_STORE[str(assessment_id)] = dict(row)
        logger.info("Loaded %d skill assessments from disk", len(SKILL_ASSESSMENT_STORE))
    except Exception as exc:
        logger.warning("Failed to load skill assessment store: %s", exc)


def _save_skill_assessment_store() -> None:
    path = _skill_assessment_store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"assessments": SKILL_ASSESSMENT_STORE}, f, indent=2, default=_json_default)
    except Exception as exc:
        logger.warning("Failed to save skill assessment store: %s", exc)


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
        "source": "verityflux",
        "event_type": event_type,
        "actor": {"agent_id": agent_id},
        "request": {"session_id": session_id, "trace_id": trace_id},
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
        "api_key": target.api_key,
        "base_url": target.endpoint_url,
        "is_agent": target.config.get("is_agent", False),
        "has_tools": target.config.get("has_tools", False),
        "has_memory": target.config.get("has_memory", False),
        "has_rag": target.config.get("has_rag", False),
        "has_approval_workflow": target.config.get("has_approval_workflow", False),
        "has_identity_verification": target.config.get("has_identity_verification", False),
        "has_rbac": target.config.get("has_rbac", False),
        "has_sandbox": target.config.get("has_sandbox", False),
        "has_code_validation": target.config.get("has_code_validation", False),
        "has_cost_controls": target.config.get("has_cost_controls", False),
        "has_monitoring": target.config.get("has_monitoring", False),
        "has_kill_switch": target.config.get("has_kill_switch", False),
        "has_circuit_breaker": target.config.get("has_circuit_breaker", False),
        "has_error_isolation": target.config.get("has_error_isolation", False),
        "codebase_path": target.config.get("codebase_path"),
        "vector_store_url": target.config.get("vector_store_url"),
        "system_prompt": target.config.get("system_prompt"),
        "extra": target.config,
    }


def _run_scan_job(scan_id: str, target: "ScanTargetRequest", config: Optional["ScanConfigRequest"], user: Dict):
    started_at = SCAN_STORE[scan_id]["started_at"]
    SCAN_STORE[scan_id]["status"] = "running"
    try:
        # ------------------------------------------------------------------
        # Pre-scan credential validation — refuse to start if creds are bad
        # ------------------------------------------------------------------
        from integrations.llm_adapter import LLMAdapter
        provider = target.target_type or "mock"
        if provider not in ("mock",):
            test_adapter = LLMAdapter(
                provider=provider,
                model=target.model_name or "gpt-3.5-turbo",
                api_key=target.api_key,
                base_url=target.endpoint_url,
            )
            cred_ok, cred_detail = test_adapter.validate_credentials()
            if not cred_ok:
                SCAN_STORE[scan_id].update({
                    "status": "failed",
                    "error": f"Credential validation failed: {cred_detail}",
                    "completed_at": datetime.utcnow(),
                })
                _save_scan_store()
                _emit_integration_event(
                    event_type="scan_failed",
                    agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
                    status="error",
                    reason=f"Credential validation failed: {cred_detail}",
                    evidence={"scan_id": scan_id, "target": target.name},
                    correlation_id=scan_id,
                )
                return
            SCAN_STORE[scan_id]["credential_validated"] = True

        # Merge fuzz/mcp flags from both target.config and API config
        _fuzz = bool(target.config.get("scan_fuzz_threats", False))
        _mcp = bool(target.config.get("scan_mcp_threats", False))
        if config:
            _fuzz = _fuzz or bool(getattr(config, "scan_fuzz_threats", False))
            _mcp = _mcp or bool(getattr(config, "scan_mcp_threats", False))
        scan_config = ScanConfig(
            scan_llm_threats=True,
            scan_agentic_threats=True,
            scan_fuzz_threats=_fuzz,
            scan_mcp_threats=_mcp,
            max_test_samples=5 if (config and config.profile == "quick") else 10,
            timeout_seconds=30,
            verbose=False,
        )
        scanner = VerityFluxScanner(application_name=target.name, config=scan_config)
        report = scanner.scan_all(_build_target_dict(target))

        findings = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for threat in report.all_threats:
            if not threat.detected:
                continue
            threat_type = str(threat.threat_type or "")
            threat_type_upper = threat_type.upper()
            severity = threat.risk_level.value if isinstance(threat.risk_level, RiskLevel) else str(threat.risk_level)
            summary[severity] = summary.get(severity, 0) + 1
            findings.append(ScanFindingResponse(
                id=f"{scan_id}:{threat_type}",
                vuln_id=threat_type_upper,
                title=threat_type_upper,
                severity=severity,
                status="confirmed",
                target_name=target.name,
                component="agentic" if threat_type.lower().startswith("aai") else "llm",
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
            total_tests=len(report.all_threats),
            passed_tests=len(report.all_threats) - report.total_threats,
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
        _save_scan_store()

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
            correlation_id=scan_id,
        )
    except Exception as exc:
        SCAN_STORE[scan_id].update({
            "status": "failed",
            "error": str(exc),
            "completed_at": datetime.utcnow(),
        })
        _save_scan_store()
        _emit_integration_event(
            event_type="scan_failed",
            agent_id=user.get("user_id", "unknown") if isinstance(user, dict) else "unknown",
            status="error",
            reason=str(exc),
            evidence={"scan_id": scan_id, "target": target.name},
            correlation_id=scan_id,
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

    @model_validator(mode="before")
    @classmethod
    def _extract_api_key(cls, values):
        """Extract api_key from nested credentials if not provided at top level (backward compat)."""
        if isinstance(values, dict) and not values.get("api_key"):
            # Try credentials dict at top level
            creds = values.get("credentials")
            if isinstance(creds, dict) and creds.get("api_key"):
                values["api_key"] = creds["api_key"]
            else:
                # Try config.credentials
                cfg = values.get("config")
                if isinstance(cfg, dict):
                    cfg_creds = cfg.get("credentials")
                    if isinstance(cfg_creds, dict) and cfg_creds.get("api_key"):
                        values["api_key"] = cfg_creds["api_key"]
        return values


class ScanConfigRequest(BaseModel):
    profile: str = "standard"  # quick, standard, deep, compliance
    vuln_ids: Optional[List[str]] = None
    exclude_vuln_ids: List[str] = Field(default_factory=list)
    max_requests_per_vuln: int = 5
    concurrent_tests: int = 3
    include_evidence: bool = True
    scan_fuzz_threats: bool = False
    scan_mcp_threats: bool = False


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


class SkillAssessmentRequest(BaseModel):
    name: str
    content: str
    primary_filename: str = "skill.md"
    platform: Optional[str] = None
    source: str = "manual"
    supporting_files: Dict[str, str] = Field(default_factory=dict)


class SkillFindingResponse(BaseModel):
    ast_id: str
    title: str
    severity: str
    risk_score: float
    summary: str
    evidence: List[str]
    recommendations: List[str]


class SkillAssessmentResponse(BaseModel):
    assessment_id: str
    name: str
    platform: str
    primary_filename: str
    source: str
    generated_at: str
    normalized_manifest: Dict[str, Any]
    finding_count: int
    overall_risk_score: float
    overall_severity: str
    findings: List[SkillFindingResponse]
    mapped_controls: Dict[str, List[str]]
    created_by: str


class ASTGapRowResponse(BaseModel):
    ast_id: str
    title: str
    assessment_coverage: str
    suite_controls: List[str]
    residual_gap: str


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
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    has_sandbox: bool = False
    has_approval_workflow: bool = False
    has_identity_verification: bool = False
    has_rbac: bool = False
    has_memory: bool = False
    has_rag: bool = False
    has_code_validation: bool = False
    has_cost_controls: bool = False
    has_monitoring: bool = False
    has_kill_switch: bool = False
    codebase_path: Optional[str] = None
    vector_store_url: Optional[str] = None
    system_prompt: Optional[str] = None


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
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    codebase_path: Optional[str] = None
    vector_store_url: Optional[str] = None
    system_prompt: Optional[str] = None
    has_sandbox: bool = False
    has_approval_workflow: bool = False
    has_identity_verification: bool = False
    has_rbac: bool = False
    has_memory: bool = False
    has_rag: bool = False
    has_code_validation: bool = False
    has_cost_controls: bool = False
    has_monitoring: bool = False
    has_kill_switch: bool = False


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
        endpoint_url=agent.get("endpoint_url"),
        api_key=agent.get("api_key"),
        codebase_path=agent.get("codebase_path"),
        vector_store_url=agent.get("vector_store_url"),
        system_prompt=agent.get("system_prompt"),
        has_sandbox=bool(agent.get("has_sandbox", False)),
        has_approval_workflow=bool(agent.get("has_approval_workflow", False)),
        has_identity_verification=bool(agent.get("has_identity_verification", False)),
        has_rbac=bool(agent.get("has_rbac", False)),
        has_memory=bool(agent.get("has_memory", False)),
        has_rag=bool(agent.get("has_rag", False)),
        has_code_validation=bool(agent.get("has_code_validation", False)),
        has_cost_controls=bool(agent.get("has_cost_controls", False)),
        has_monitoring=bool(agent.get("has_monitoring", False)),
        has_kill_switch=bool(agent.get("has_kill_switch", False)),
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
        _load_scan_store()
        _load_skill_assessment_store()

        logger.info("Services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
    
    yield
    
    # Shutdown
    _save_agent_store()
    _save_scan_store()
    _save_skill_assessment_store()
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
        correlation_id=f"policy:{user.get('user_id', 'unknown')}" if isinstance(user, dict) else "policy:unknown",
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
        correlation_id=f"policy:{user.get('user_id', 'unknown')}" if isinstance(user, dict) else "policy:unknown",
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
        correlation_id=scan_id,
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
    result = scan["result"]
    if isinstance(result, dict):
        findings = result.get("findings", [])
        if severity:
            findings = [f for f in findings if (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", None)) == severity]
    else:
        findings = result.findings
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
            if isinstance(result, dict):
                findings_summary = result.get("findings_summary", {})
                overall_risk_score = result.get("overall_risk_score")
            else:
                findings_summary = getattr(result, "findings_summary", {})
                overall_risk_score = getattr(result, "overall_risk_score", None)
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


@app.post("/api/v2/skills/assess", response_model=SkillAssessmentResponse, tags=["Skill Security"])
async def assess_skill_package(
    request: SkillAssessmentRequest,
    user: Dict = Depends(get_current_user),
):
    """
    Assess a skill manifest or package against AST01-AST10 heuristics.
    """
    _require_admin(user)
    assessor = SkillSecurityAssessor()
    assessment = assessor.assess(
        name=request.name,
        content=request.content,
        primary_filename=request.primary_filename,
        platform=request.platform,
        supporting_files=request.supporting_files,
    )
    record = assessment.to_dict()
    record["source"] = request.source
    record["created_by"] = user.get("user_id", "admin")
    SKILL_ASSESSMENT_STORE[assessment.assessment_id] = record
    _save_skill_assessment_store()

    _emit_integration_event(
        event_type="skill_assessment_completed",
        agent_id=user.get("user_id", "unknown"),
        status="success",
        evidence={
            "assessment_id": assessment.assessment_id,
            "skill_name": request.name,
            "platform": assessment.platform,
            "primary_filename": request.primary_filename,
            "overall_risk_score": assessment.overall_risk_score,
            "overall_severity": assessment.overall_severity,
            "finding_ids": [finding.ast_id for finding in assessment.findings],
            "mapped_controls": assessment.mapped_controls,
        },
        correlation_id=assessment.assessment_id,
    )
    return record


@app.get("/api/v2/skills/assessments", response_model=PaginatedResponse, tags=["Skill Security"])
async def list_skill_assessments(
    severity: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = Query(default=20, le=100),
    offset: int = 0,
    user: Dict = Depends(get_current_user),
):
    """
    List stored skill assessments.
    """
    _require_admin(user)
    rows = list(SKILL_ASSESSMENT_STORE.values())
    if severity:
        rows = [row for row in rows if str(row.get("overall_severity", "")).lower() == severity.lower()]
    if platform:
        rows = [row for row in rows if str(row.get("platform", "")).lower() == platform.lower()]
    rows.sort(key=lambda row: str(row.get("generated_at", "")), reverse=True)
    total = len(rows)
    items = rows[offset: offset + limit]
    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.get("/api/v2/skills/assessments/{assessment_id}", response_model=SkillAssessmentResponse, tags=["Skill Security"])
async def get_skill_assessment(
    assessment_id: str,
    user: Dict = Depends(get_current_user),
):
    """
    Get a stored skill assessment by id.
    """
    _require_admin(user)
    record = SKILL_ASSESSMENT_STORE.get(assessment_id)
    if not record:
        raise HTTPException(status_code=404, detail="Skill assessment not found")
    return record


@app.get("/api/v2/skills/gap-matrix", response_model=List[ASTGapRowResponse], tags=["Skill Security"])
async def get_skill_gap_matrix(
    user: Dict = Depends(get_current_user),
):
    """
    Return suite coverage status for AST01-AST10 skill-layer risks.
    """
    _require_admin(user)
    return SkillSecurityAssessor().gap_matrix()


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
        existing["endpoint_url"] = request.endpoint_url
        existing["api_key"] = request.api_key
        existing["capabilities"] = request.capabilities
        existing["has_sandbox"] = request.has_sandbox
        existing["has_approval_workflow"] = request.has_approval_workflow
        existing["has_identity_verification"] = request.has_identity_verification
        existing["has_rbac"] = request.has_rbac
        existing["has_memory"] = request.has_memory
        existing["has_rag"] = request.has_rag
        existing["has_code_validation"] = request.has_code_validation
        existing["has_cost_controls"] = request.has_cost_controls
        existing["has_monitoring"] = request.has_monitoring
        existing["has_kill_switch"] = request.has_kill_switch
        existing["codebase_path"] = request.codebase_path
        existing["vector_store_url"] = request.vector_store_url
        existing["system_prompt"] = request.system_prompt
        existing["updated_at"] = datetime.utcnow()
        _save_agent_store()
        _emit_integration_event(
            event_type="agent_updated",
            agent_id=str(existing.get("id")),
            status="success",
            evidence={"name": existing.get("name"), "environment": existing.get("environment")},
            correlation_id=str(existing.get("id")),
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
        "endpoint_url": request.endpoint_url,
        "api_key": request.api_key,
        "capabilities": request.capabilities,
        "has_sandbox": request.has_sandbox,
        "has_approval_workflow": request.has_approval_workflow,
        "has_identity_verification": request.has_identity_verification,
        "has_rbac": request.has_rbac,
        "has_memory": request.has_memory,
        "has_rag": request.has_rag,
        "has_code_validation": request.has_code_validation,
        "has_cost_controls": request.has_cost_controls,
        "has_monitoring": request.has_monitoring,
        "has_kill_switch": request.has_kill_switch,
        "codebase_path": request.codebase_path,
        "vector_store_url": request.vector_store_url,
        "system_prompt": request.system_prompt,
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
        correlation_id=agent_id,
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
        correlation_id=agent_id,
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
    
    request_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    ttl = timeout_minutes or 30
    action_desc = getattr(context, "action_description", None) or getattr(context, "action_type", None) or "action"
    record = {
        "id": request_id,
        "status": "pending",
        "risk_level": context.risk_level if hasattr(context, "risk_level") else ("critical" if context.risk_score >= 80 else "high" if context.risk_score >= 60 else "medium"),
        "title": f"{context.agent_name} wants to use {context.tool_name}",
        "description": f"Risk score: {context.risk_score}. Action: {action_desc}",
        "agent_id": context.agent_id,
        "agent_name": context.agent_name,
        "tool": context.tool_name,
        "action_type": action_desc,
        "risk_score": context.risk_score,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=ttl)).isoformat(),
        "time_remaining_seconds": ttl * 60,
        "assigned_to": ["admin"],
        "decision": None,
        "decided_by": None,
        "justification": None,
    }
    APPROVAL_STORE[request_id] = record
    return ApprovalRequestResponse(
        id=request_id,
        status="pending",
        risk_level=record["risk_level"],
        title=record["title"],
        description=record["description"],
        created_at=now,
        expires_at=now + timedelta(minutes=ttl),
        time_remaining_seconds=ttl * 60,
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
    """List approval requests from in-memory queue."""
    now = datetime.now(UTC).isoformat()
    items = list(APPROVAL_STORE.values())
    # Auto-expire
    items = [r for r in items if r.get("expires_at", "9999") > now or r.get("status") not in ("pending",)]
    if status:
        items = [r for r in items if r.get("status") == status]
    if agent_id:
        items = [r for r in items if r.get("agent_id") == agent_id]
    items.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    page = items[offset: offset + limit]
    return PaginatedResponse(
        items=page,
        total=len(items),
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < len(items),
    )


@app.get("/api/v1/approvals/pending", tags=["HITL"])
async def get_pending_approvals(user: Dict = Depends(get_current_user)):
    """Get all pending (non-expired) approvals from the in-memory queue."""
    now = datetime.now(UTC).isoformat()
    pending = [
        r for r in APPROVAL_STORE.values()
        if r.get("status") == "pending" and r.get("expires_at", "9999") > now
    ]
    pending.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return pending


@app.get("/api/v1/approvals/{request_id}", tags=["HITL"])
async def get_approval_request(
    request_id: str,
    user: Dict = Depends(get_current_user)
):
    """Get approval request by ID from in-memory queue."""
    record = APPROVAL_STORE.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return record


@app.post("/api/v1/approvals/{request_id}/decide", tags=["HITL"])
async def decide_approval(
    request_id: str,
    request: ApprovalDecisionRequest,
    user: Dict = Depends(get_current_user)
):
    """Record a human decision on a pending approval request."""
    record = APPROVAL_STORE.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="Approval request not found")
    record["status"] = request.decision if request.decision in ("approve", "deny", "escalate") else "decided"
    record["decided_by"] = user.get("user_id", "admin")
    record["justification"] = request.justification
    record["decided_at"] = datetime.now(UTC).isoformat()
    return {"success": True, "message": f"Request {request_id} {record['status']}", "record": record}


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
    cutoff = (datetime.now(UTC) - timedelta(hours=period_hours)).isoformat()
    records = [r for r in APPROVAL_STORE.values() if r.get("created_at", "") >= cutoff]
    by_status: Dict[str, int] = {}
    for r in records:
        s = r.get("status", "pending")
        by_status[s] = by_status.get(s, 0) + 1
    return ApprovalStatsResponse(
        total_requests=len(records),
        by_status=by_status,
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
# ENTERPRISE FEATURES - Runtime Interception & Advanced Detection
# =============================================================================

# Lazy-init enterprise modules
_reasoning_interceptor = None
_rationalization_engine = None
_memory_filter = None
_adversarial_scorer = None
_intent_tracker = None
_manifest_signer = None
_schema_validator = None
_protocol_integrity_analyzer = None
_supply_chain = None
_flight_recorder = None


def _get_reasoning_interceptor():
    global _reasoning_interceptor
    if _reasoning_interceptor is None:
        from cognitive_firewall.reasoning_interceptor import ReasoningInterceptor
        from cognitive_firewall.rationalization_engine import RationalizationEngine
        _re = RationalizationEngine()
        _reasoning_interceptor = ReasoningInterceptor(rationalization_engine=_re)
    return _reasoning_interceptor


def _get_rationalization_engine():
    global _rationalization_engine
    if _rationalization_engine is None:
        from cognitive_firewall.rationalization_engine import RationalizationEngine
        _rationalization_engine = RationalizationEngine()
    return _rationalization_engine


def _get_memory_filter():
    global _memory_filter
    if _memory_filter is None:
        from cognitive_firewall.memory_runtime_filter import MemoryRuntimeFilter
        _memory_filter = MemoryRuntimeFilter()
    return _memory_filter


def _get_adversarial_scorer():
    global _adversarial_scorer
    if _adversarial_scorer is None:
        from cognitive_firewall.adversarial_scorer import AdversarialLLMScorer
        _adversarial_scorer = AdversarialLLMScorer()
    return _adversarial_scorer


def _get_intent_tracker():
    global _intent_tracker
    if _intent_tracker is None:
        from cognitive_firewall.stateful_intent_tracker import StatefulIntentTracker
        _intent_tracker = StatefulIntentTracker()
    return _intent_tracker


def _get_flight_recorder():
    global _flight_recorder
    if _flight_recorder is None:
        from cognitive_firewall.flight_recorder import EnterpriseFlightRecorder
        from pathlib import Path as _FP
        _vf_root = str(_FP(__file__).resolve().parents[2])
        _flight_recorder = EnterpriseFlightRecorder(log_dir=str(_FP(_vf_root) / "flight_logs"))
    return _flight_recorder


def _get_manifest_signer():
    global _manifest_signer
    if _manifest_signer is None:
        from cognitive_firewall.tool_manifest_signer import ToolManifestSigner
        _manifest_signer = ToolManifestSigner()
    return _manifest_signer


def _get_schema_validator():
    global _schema_validator
    if _schema_validator is None:
        from cognitive_firewall.schema_validator import SchemaValidator
        _schema_validator = SchemaValidator()
    return _schema_validator


def _get_protocol_integrity_analyzer():
    global _protocol_integrity_analyzer
    if _protocol_integrity_analyzer is None:
        _protocol_integrity_analyzer = ProtocolIntegrityAnalyzer()
    return _protocol_integrity_analyzer


def _build_protocol_expected_contract(
    *,
    tool_name: str,
    agent_id: str,
    session_id: Optional[str],
    schema_version: Optional[str],
    contract_id: Optional[str],
) -> Dict[str, Any]:
    schema_validator = _get_schema_validator()
    contract = schema_validator.get_input_contract(tool_name)
    contract["required_top_fields"] = ["agent_id", "tool_name", "arguments"]
    contract["allowed_top_fields"] = [
        "agent_id", "tool_name", "arguments", "session_id", "schema_version",
        "contract_id", "metadata", "route", "protocol",
    ]
    contract["schema_version"] = schema_version or "1"
    contract["bindings"] = {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "session_id": session_id,
    }
    if contract_id:
        contract["contract_id"] = contract_id
    return contract


def _assess_protocol_integrity(
    *,
    protocol: str,
    agent_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    session_id: Optional[str],
    schema_version: Optional[str],
    contract_id: Optional[str],
    route: Optional[List[Dict[str, Any]]],
    metadata: Optional[Dict[str, Any]],
    identity_result: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    analyzer = _get_protocol_integrity_analyzer()
    payload = {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "session_id": session_id,
        "schema_version": schema_version or "1",
        "contract_id": contract_id or f"{protocol}:{tool_name}:v{schema_version or '1'}",
        "protocol": protocol,
        "metadata": metadata or {},
        "route": route or [],
    }
    expected_contract = _build_protocol_expected_contract(
        tool_name=tool_name,
        agent_id=agent_id,
        session_id=session_id,
        schema_version=schema_version,
        contract_id=contract_id,
    )
    identity_context = {
        "valid": bool((identity_result or {}).get("valid", True)),
        "agent_id": agent_id,
        "tool_name": tool_name,
        "session_id": session_id,
        "has_sender_binding": bool(identity_result and identity_result.get("valid")),
    }
    assessment = analyzer.analyze(
        protocol=protocol,
        payload=payload,
        expected_contract=expected_contract,
        route=route or [],
        identity_context=identity_context,
    )
    entry = assessment.to_dict()
    entry.update({
        "agent_id": agent_id,
        "tool_name": tool_name,
        "session_id": session_id,
        "has_findings": assessment.finding_count > 0,
    })
    _append_capped(MCP_PROTOCOL_LOG, entry)
    return entry


def _get_supply_chain():
    global _supply_chain
    if _supply_chain is None:
        from cognitive_firewall.supply_chain_monitor import SupplyChainMonitor
        _supply_chain = SupplyChainMonitor()
    return _supply_chain


# --- Reasoning Interceptor Endpoints ---

class InterceptReasoningRequest(BaseModel):
    agent_id: str
    thinking_block: str
    original_goal: str
    reasoning_chain: Optional[List[str]] = None
    session_id: Optional[str] = None
    handoff_from_agent_id: Optional[str] = None
    handoff_channel: Optional[str] = None
    handoff_shared_reasoning: bool = False
    handoff_metadata: Optional[Dict[str, Any]] = None

@app.post("/api/v2/intercept/reasoning", tags=["Enterprise"])
async def intercept_reasoning(req: InterceptReasoningRequest):
    """Intercept and evaluate an agent's reasoning block in real-time."""
    interceptor = _get_reasoning_interceptor()
    result = interceptor.intercept_reasoning(
        agent_id=req.agent_id,
        thinking_block=req.thinking_block,
        original_goal=req.original_goal,
        reasoning_chain=req.reasoning_chain,
        handoff_from_agent_id=req.handoff_from_agent_id,
        handoff_channel=req.handoff_channel,
        handoff_shared_reasoning=req.handoff_shared_reasoning,
        handoff_metadata=req.handoff_metadata,
    )
    if result.contamination_detected:
        _emit_integration_event(
            event_type="REASONING_A2A_ALERT",
            agent_id=req.agent_id,
            status="CRITICAL" if result.action == "block" else "WARNING",
            reason="A2A chain-of-thought contamination detected in inherited reasoning",
            session_id=req.session_id,
            evidence={
                "summary": "Inherited reasoning contained unsafe or unvalidated prior-agent control content",
                "handoff_from_agent_id": req.handoff_from_agent_id,
                "handoff_channel": req.handoff_channel,
                "contamination_score": result.contamination_score,
                "findings": result.contamination_findings,
            },
        )
    _append_capped(ENFORCEMENT_LOG, {
        "timestamp": datetime.now(UTC).isoformat(),
        "module": "reasoning",
        "mode": ENFORCEMENT_MODE,
        "action": result.action,
        "risk_score": result.risk_score,
        "agent_id": req.agent_id,
        "tool_name": None,
        "violations": result.violations,
        "reasoning": result.reasoning,
        "contamination_detected": result.contamination_detected,
        "contamination_score": result.contamination_score,
    })
    return {
        "action": result.action,
        "risk_score": result.risk_score,
        "reasoning": result.reasoning,
        "violations": result.violations,
        "contamination_detected": result.contamination_detected,
        "contamination_score": result.contamination_score,
        "contamination_findings": result.contamination_findings,
        "integrity_score": result.integrity_score,
        "drift_score": result.drift_score,
    }


class InterceptToolCallRequest(BaseModel):
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any]
    reasoning_context: Optional[str] = None
    original_goal: Optional[str] = None
    session_id: Optional[str] = None
    protocol: Optional[str] = "mcp"
    schema_version: Optional[str] = "1"
    contract_id: Optional[str] = None
    route: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    mcp_tool_token: Optional[str] = None
    sandbox_attested: bool = False

@app.post("/api/v2/intercept/tool-call", tags=["Enterprise"])
async def intercept_tool_call(req: InterceptToolCallRequest):
    """Intercept a tool call before execution."""
    identity_result = {"valid": True, "reason": "not_provided"}
    if req.mcp_tool_token:
        identity_result = _mcp_verify(
            req.mcp_tool_token,
            expected_agent_id=req.agent_id,
            expected_tool_name=req.tool_name,
            expected_session_id=req.session_id,
        )
        if not identity_result.get("valid"):
            out = {
                "action": "block",
                "risk_score": 95.0,
                "reasoning": f"MCP identity guard denied call: {identity_result.get('reason')}",
                "violations": [f"MCP identity guard: {identity_result.get('reason')}"],
                "schema_valid": False,
                "schema_errors": [],
                "identity_valid": False,
            }
            _append_capped(ENFORCEMENT_LOG, {
                "timestamp": datetime.now(UTC).isoformat(),
                "module": "tool_call",
                "mode": ENFORCEMENT_MODE,
                "action": out["action"],
                "risk_score": out["risk_score"],
                "agent_id": req.agent_id,
                "tool_name": req.tool_name,
                "reason": out["reasoning"],
            })
            return out

    schema_validator = _get_schema_validator()
    schema_result = schema_validator.validate_input(req.tool_name, req.arguments)
    _append_capped(
        MCP_SCHEMA_LOG,
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool_name": req.tool_name,
            "agent_id": req.agent_id,
            "valid": bool(schema_result.get("valid", True)),
            "errors": schema_result.get("errors", []),
            "schema_registered": req.tool_name in schema_validator.get_registered_tools(),
        },
    )
    protocol_result = _assess_protocol_integrity(
        protocol=(req.protocol or "mcp"),
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        arguments=req.arguments,
        session_id=req.session_id,
        schema_version=req.schema_version,
        contract_id=req.contract_id,
        route=req.route,
        metadata=req.metadata,
        identity_result=identity_result,
    )

    interceptor = _get_reasoning_interceptor()
    result = interceptor.intercept_tool_call(
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        arguments=req.arguments,
        reasoning_context=req.reasoning_context,
        original_goal=req.original_goal,
    )
    containment = _runtime_containment_checks(req.tool_name, req.arguments, sandbox_attested=req.sandbox_attested)
    action = result.action
    risk = float(result.risk_score)
    reasoning = result.reasoning
    violations = list(result.violations) + schema_result.get("errors", []) + containment.get("violations", [])
    protocol_findings = protocol_result.get("findings", [])
    for finding in protocol_findings:
        title = finding.get("title", "Protocol integrity issue")
        for detail in finding.get("evidence", [])[:3]:
            violations.append(f"{title}: {detail}")
    if not containment.get("valid", True):
        risk = max(risk, 85.0)
        action = "block" if ENFORCEMENT_MODE == "enforce" else "escalate"
        reasoning = "Runtime containment policy violation"
    if protocol_result.get("finding_count", 0) > 0:
        risk = max(risk, float(protocol_result.get("overall_risk_score", 0.0)))
        proto_sev = str(protocol_result.get("overall_severity", "low"))
        if proto_sev == "critical":
            action = "block" if ENFORCEMENT_MODE == "enforce" else "escalate"
        elif proto_sev in ("high", "medium") and action == "allow":
            action = "escalate"
        reasoning = "Protocol integrity policy violation" if action != "allow" else "Protocol integrity warning"
        _emit_integration_event(
            event_type="PROTOCOL_INTEGRITY_ALERT",
            agent_id=req.agent_id,
            status="CRITICAL" if proto_sev == "critical" else "WARNING",
            reason=reasoning,
            session_id=req.session_id,
            evidence={
                "summary": f"Protocol integrity alert for {req.tool_name}",
                "protocol": req.protocol or "mcp",
                "overall_severity": proto_sev,
                "risk_score": protocol_result.get("overall_risk_score"),
                "findings": protocol_findings,
            },
        )

    _append_capped(ENFORCEMENT_LOG, {
        "timestamp": datetime.now(UTC).isoformat(),
        "module": "tool_call",
        "mode": ENFORCEMENT_MODE,
        "action": action,
        "risk_score": risk,
        "agent_id": req.agent_id,
        "tool_name": req.tool_name,
        "identity_valid": identity_result.get("valid", True),
        "containment_valid": containment.get("valid", True),
        "protocol_findings": protocol_result.get("finding_count", 0),
    })
    return {
        "action": action,
        "risk_score": risk,
        "reasoning": reasoning,
        "violations": violations,
        "schema_valid": bool(schema_result.get("valid", True)),
        "schema_errors": schema_result.get("errors", []),
        "identity_valid": identity_result.get("valid", True),
        "containment_valid": containment.get("valid", True),
        "protocol_integrity": protocol_result,
    }


# --- Rationalization Engine Endpoint ---

class RationalizeRequest(BaseModel):
    action_description: str
    actor_reasoning: str
    agent_context: Optional[Dict[str, Any]] = None

@app.post("/api/v2/rationalize", tags=["Enterprise"])
async def rationalize_action(req: RationalizeRequest):
    """Run independent LLM-as-a-Judge rationalization on a proposed action."""
    engine = _get_rationalization_engine()
    result = engine.rationalize(
        action_description=req.action_description,
        actor_reasoning=req.actor_reasoning,
        agent_context=req.agent_context,
    )
    payload = {
        "is_safe": result.is_safe,
        "confidence": result.confidence,
        "oversight_reasoning": result.oversight_reasoning,
        "divergence_from_actor": result.divergence_from_actor,
        "recommended_action": result.recommended_action,
        "risk_factors": result.risk_factors,
    }
    _append_capped(
        RATIONALE_LOG,
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "action_description": req.action_description,
            "actor_reasoning": req.actor_reasoning,
            **payload,
        },
    )
    return payload


# --- Memory Filter Endpoint ---

class FilterMemoryRequest(BaseModel):
    retrievals: List[Dict[str, Any]]
    agent_context: Optional[Dict[str, Any]] = None

@app.post("/api/v2/filter/memory", tags=["Enterprise"])
async def filter_memory(req: FilterMemoryRequest):
    """Filter RAG/memory retrievals for poisoning and injection."""
    mf = _get_memory_filter()
    result = mf.filter_retrievals(req.retrievals, req.agent_context)
    payload = {
        "cleaned_retrievals": result.cleaned_retrievals,
        "filtered_retrievals": result.cleaned_retrievals,
        "removed_count": result.removed_count,
        "modified_count": result.modified_count,
        "threats_found": result.threats_found,
        "audit_trail": result.audit_trail,
        "cross_agent_alert": result.cross_agent_alert,
        "cross_agent_findings": result.cross_agent_findings,
        "risk_score": result.risk_score,
    }
    agent_context = req.agent_context or {}
    agent_id = (
        agent_context.get("agent_id")
        or agent_context.get("requesting_agent_id")
        or agent_context.get("actor_id")
        or "unknown-agent"
    )
    session_id = agent_context.get("session_id")
    if result.removed_count or result.modified_count or result.threats_found:
        _emit_integration_event(
            event_type="MEMORY_FILTERED",
            agent_id=agent_id,
            status="warning" if result.cross_agent_alert else "success",
            reason="Memory retrieval sanitization applied",
            session_id=session_id,
            evidence={
                "removed_count": result.removed_count,
                "modified_count": result.modified_count,
                "threats_found": result.threats_found,
                "cross_agent_alert": result.cross_agent_alert,
                "risk_score": result.risk_score,
            },
        )
    if result.cross_agent_alert:
        _emit_integration_event(
            event_type="MEMORY_CROSS_AGENT_ALERT",
            agent_id=agent_id,
            status="warning",
            reason="Cross-agent working-memory poisoning risk detected",
            session_id=session_id,
            evidence={
                "findings": result.cross_agent_findings,
                "risk_score": result.risk_score,
            },
        )
    return payload


# --- Adversarial Scorer Endpoint ---

class ScoreAdversarialRequest(BaseModel):
    input_text: str
    context: Optional[Dict[str, Any]] = None

@app.post("/api/v2/score/adversarial", tags=["Enterprise"])
async def score_adversarial(req: ScoreAdversarialRequest):
    """Score input text for adversarial intent."""
    scorer = _get_adversarial_scorer()
    result = scorer.score_input(req.input_text, req.context)
    return {
        "hostility_score": result.hostility_score,
        "risk_score": round(float(result.hostility_score) * 100.0, 2),
        "intent_class": result.intent_class,
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "is_adversarial": result.is_adversarial,
    }


# --- Session Drift Tracker Endpoints ---

class TrackInteractionRequest(BaseModel):
    agent_id: str
    user_input: str
    agent_response: str
    tool_calls: Optional[List[Dict[str, Any]]] = None

@app.post("/api/v2/session/{session_id}/track", tags=["Enterprise"])
async def track_session_interaction(session_id: str, req: TrackInteractionRequest):
    """Track an interaction within a session for drift monitoring."""
    tracker = _get_intent_tracker()
    result = tracker.track_interaction(
        session_id=session_id,
        agent_id=req.agent_id,
        user_input=req.user_input,
        agent_response=req.agent_response,
        tool_calls=req.tool_calls,
    )
    return {
        "drift_score": result.drift_score,
        "drift_rate": result.drift_rate,
        "is_crescendo": result.is_crescendo,
        "explanation": result.explanation,
        "alert_level": result.alert_level,
    }

@app.get("/api/v2/session/{session_id}/state", tags=["Enterprise"])
async def get_session_state(session_id: str):
    """Get current drift state for a session."""
    tracker = _get_intent_tracker()
    state = tracker.get_session_state(session_id)
    if not state:
        raise HTTPException(404, f"Session '{session_id}' not found")
    return {
        "session_id": state.session_id,
        "turn_count": state.turn_count,
        "current_drift": state.current_drift,
        "alert_level": state.alert_level,
        "flagged_turns": state.flagged_turns,
        "drift_history": state.drift_history,
    }


@app.get("/api/v2/sessions", tags=["Enterprise"])
async def list_session_states(limit: int = Query(default=100, ge=1, le=500)):
    """List active tracked sessions for the Session Drift dashboard."""
    tracker = _get_intent_tracker()
    sessions: List[Dict[str, Any]] = []
    for state in getattr(tracker, "_sessions", {}).values():
        sessions.append({
            "session_id": state.session_id,
            "turn_count": state.turn_count,
            "drift_score": state.current_drift,
            "alert_level": state.alert_level,
            "flagged_turns": len(state.flagged_turns),
            "last_updated": state.last_updated,
        })
    sessions.sort(key=lambda s: s.get("last_updated", ""), reverse=True)
    return sessions[:limit]


@app.get("/api/v2/telemetry/reasoning", tags=["Enterprise"])
async def list_reasoning_telemetry(limit: int = Query(default=100, ge=1, le=1000)):
    """Recent reasoning/tool-call interception telemetry from flight logs."""
    activity: List[Dict[str, Any]] = []
    try:
        from glob import glob
        flight_dir = BASE_DIR / "flight_logs"
        for fp in glob(str(flight_dir / "*.jsonl")):
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    decision = row.get("firewall_decision", {})
                    activity.append({
                        "timestamp": row.get("timestamp"),
                        "agent_id": row.get("agent_id"),
                        "tool_name": row.get("tool_name"),
                        "action": decision.get("action"),
                        "risk_score": decision.get("risk_score"),
                        "reasoning": decision.get("reasoning"),
                        "source": "flight_log",
                    })
    except Exception:
        pass
    activity.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return activity[:limit]


@app.get("/api/v2/telemetry/rationalizations", tags=["Enterprise"])
async def list_rationalizations(limit: int = Query(default=100, ge=1, le=1000)):
    """Recent rationalization results from oversight model evaluations."""
    return list(reversed(RATIONALE_LOG[-limit:]))


def _atlas_techniques_for_row(row: Dict[str, Any]) -> List[str]:
    text = " ".join([
        str(row.get("tool_name", "")),
        str(row.get("reasoning", "")),
        " ".join(str(v) for v in row.get("violations", []) if v),
    ]).lower()
    mapped: List[str] = []
    if any(k in text for k in ("ignore instructions", "jailbreak", "prompt", "bypass")):
        mapped.append("AML.T0051")  # Prompt Injection (ATLAS style mapping)
    if any(k in text for k in ("path traversal", "/etc/passwd", "drop table", "sql")):
        mapped.append("AML.T0015")  # Data/command injection class
    if any(k in text for k in ("token", "credential", "exfiltration")):
        mapped.append("AML.T0029")  # Credential theft / leakage class
    if any(k in text for k in ("sandbox", "containment")):
        mapped.append("AML.T0043")  # Sandbox/policy bypass class
    return sorted(set(mapped))


@app.get("/api/v2/soc/alerts/export", tags=["Enterprise"])
async def export_soc_alerts(
    format: str = Query(default="ecs", pattern="^(ecs|ocsf|atlas)$"),
    limit: int = Query(default=200, ge=1, le=5000),
    user: Dict = Depends(get_current_user),
):
    """
    Export SOC alerts in SIEM-friendly schemas.
    - ecs: Elastic Common Schema-like
    - ocsf: OCSF-like finding schema
    - atlas: compact ATT&CK/ATLAS-enriched format
    """
    _require_admin(user)
    rows = list(reversed(ENFORCEMENT_LOG[-limit:]))
    if format == "atlas":
        return [{
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "tool_name": r.get("tool_name"),
            "action": r.get("action"),
            "risk_score": r.get("risk_score"),
            "mode": r.get("mode"),
            "atlas_techniques": _atlas_techniques_for_row(r),
        } for r in rows]
    if format == "ocsf":
        return [{
            "time": r.get("timestamp"),
            "category_name": "Application Activity",
            "class_name": "Security Finding",
            "severity": int(min(10, max(1, round(float(r.get("risk_score", 0)) / 10.0)))),
            "status": r.get("action"),
            "activity_name": "agent_tool_call_enforcement",
            "metadata": {
                "agent_id": r.get("agent_id"),
                "tool_name": r.get("tool_name"),
                "mode": r.get("mode"),
                "atlas_techniques": _atlas_techniques_for_row(r),
            },
        } for r in rows]
    # ecs
    return [{
        "@timestamp": r.get("timestamp"),
        "event.kind": "alert",
        "event.category": ["security"],
        "event.type": ["info" if r.get("action") == "allow" else "denied"],
        "event.action": r.get("action"),
        "event.severity": int(min(100, max(0, round(float(r.get("risk_score", 0)))))),
        "rule.name": "verityflux_runtime_enforcement",
        "rule.category": "ai-agent-security",
        "source.user.id": r.get("agent_id"),
        "service.name": "verityflux",
        "mcp.tool.name": r.get("tool_name"),
        "labels.mode": r.get("mode"),
        "threat.framework": "MITRE ATLAS",
        "threat.technique.id": _atlas_techniques_for_row(r),
    } for r in rows]


@app.get("/api/v2/efficacy/report", tags=["Enterprise"])
async def get_efficacy_report(
    period_hours: int = Query(default=24, ge=1, le=168),
    user: Dict = Depends(get_current_user),
):
    """Live prevention efficacy report from runtime enforcement telemetry."""
    _require_admin(user)
    cutoff = (datetime.now(UTC) - timedelta(hours=period_hours)).isoformat()
    recent = [r for r in ENFORCEMENT_LOG if str(r.get("timestamp", "")) >= cutoff]
    total = len(recent)
    by_action: Dict[str, int] = {}
    by_module: Dict[str, int] = {}
    blocked = 0
    escalated = 0
    allowed = 0
    for r in recent:
        act = str(r.get("action", "unknown"))
        mod = str(r.get("module", "unknown"))
        by_action[act] = by_action.get(act, 0) + 1
        by_module[mod] = by_module.get(mod, 0) + 1
        if act == "block":
            blocked += 1
        elif act == "escalate":
            escalated += 1
        elif act == "allow":
            allowed += 1

    preventable_actions = blocked if ENFORCEMENT_MODE == "enforce" else 0
    return {
        "mode": ENFORCEMENT_MODE,
        "window_hours": period_hours,
        "total_decisions": total,
        "by_action": by_action,
        "by_module": by_module,
        "blocked": blocked,
        "escalated": escalated,
        "allowed": allowed,
        "block_rate_pct": round((blocked / total * 100.0), 2) if total else 0.0,
        "escalation_rate_pct": round((escalated / total * 100.0), 2) if total else 0.0,
        "prevented_actions": preventable_actions,
        "residual_risk_actions": escalated + (blocked if ENFORCEMENT_MODE != "enforce" else 0),
        "updated_at": datetime.now(UTC).isoformat(),
    }


@app.get("/api/v2/mcp/status", tags=["Enterprise"])
async def get_mcp_status(limit: int = Query(default=200, ge=1, le=1000)):
    """Live MCP status: signed manifests, rug-pull alerts, and schema validation stats."""
    signer = _get_manifest_signer()
    baselines = []
    for tool_name in signer.list_signed_tools():
        baseline = signer.get_baseline(tool_name)
        if not baseline:
            continue
        baselines.append({
            "tool_name": tool_name,
            "manifest_hash": baseline.manifest_hash,
            "signed_at": baseline.signed_at,
            "status": "signed",
        })

    recent_schema = MCP_SCHEMA_LOG[-limit:]
    violations = [r for r in recent_schema if not r.get("valid", True)]
    recent_protocol = MCP_PROTOCOL_LOG[-limit:]
    protocol_alerts = [r for r in recent_protocol if r.get("finding_count", 0) > 0]
    return {
        "manifests": baselines,
        "rug_pull_alerts": list(reversed(MCP_RUGPULL_LOG[-limit:])),
        "schema": {
            "validated_calls": len(recent_schema),
            "violations": len(violations),
            "recent_violations": list(reversed(violations[-25:])),
        },
        "protocol_integrity": {
            "assessed_messages": len(recent_protocol),
            "alerts": len(protocol_alerts),
            "recent_alerts": list(reversed(protocol_alerts[-25:])),
        },
        "updated_at": datetime.now(UTC).isoformat(),
    }


class ProtocolIntegrityAnalyzeRequest(BaseModel):
    protocol: str = "mcp"
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any]
    session_id: Optional[str] = None
    schema_version: Optional[str] = "1"
    contract_id: Optional[str] = None
    route: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    identity_valid: bool = True
    has_sender_binding: bool = False


@app.post("/api/v2/mcp/protocol-integrity/analyze", tags=["Enterprise"])
async def analyze_protocol_integrity(req: ProtocolIntegrityAnalyzeRequest, user: Dict = Depends(get_current_user)):
    """Analyze a structured A2A/MCP message for protocol integrity failures."""
    identity_result = {
        "valid": req.identity_valid,
        "payload": {
            "sub": user.get("user_id", "unknown"),
        },
    } if req.has_sender_binding else {"valid": req.identity_valid}
    result = _assess_protocol_integrity(
        protocol=req.protocol,
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        arguments=req.arguments,
        session_id=req.session_id,
        schema_version=req.schema_version,
        contract_id=req.contract_id,
        route=req.route,
        metadata=req.metadata,
        identity_result=identity_result,
    )
    if result.get("finding_count", 0) > 0:
        sev = str(result.get("overall_severity", "warning")).upper()
        _emit_integration_event(
            event_type="PROTOCOL_INTEGRITY_ALERT",
            agent_id=req.agent_id,
            status="CRITICAL" if sev == "CRITICAL" else "WARNING",
            reason="Explicit protocol integrity analysis found issues",
            session_id=req.session_id,
            evidence={
                "summary": f"Protocol integrity analysis flagged {req.tool_name}",
                "protocol": req.protocol,
                "overall_severity": result.get("overall_severity"),
                "risk_score": result.get("overall_risk_score"),
                "findings": result.get("findings", []),
            },
        )
    return result


class MCPIssueTokenRequest(BaseModel):
    agent_id: str
    tool_name: str
    session_id: str
    ttl_seconds: int = Field(default=120, ge=30, le=900)


@app.post("/api/v2/mcp/issue-tool-token", tags=["Enterprise"])
async def issue_mcp_tool_token(req: MCPIssueTokenRequest, user: Dict = Depends(get_current_user)):
    """Issue a short-lived sender-constrained MCP tool token."""
    now = int(datetime.now(UTC).timestamp())
    payload = {
        "jti": f"mcp_{uuid.uuid4().hex}",
        "sub": user.get("user_id", "unknown"),
        "agent_id": req.agent_id,
        "tool_name": req.tool_name,
        "session_id": req.session_id,
        "aud": "verityflux-api",
        "iat": now,
        "exp": now + int(req.ttl_seconds),
        "nonce": secrets.token_hex(8),
    }
    token = _mcp_sign(payload)
    MCP_IDENTITY_STATS["issued"] += 1
    return {
        "tool_token": token,
        "expires_at": datetime.fromtimestamp(payload["exp"], tz=UTC).isoformat(),
        "audience": payload["aud"],
    }


@app.get("/api/v2/mcp/identity/stats", tags=["Enterprise"])
async def get_mcp_identity_stats(user: Dict = Depends(get_current_user)):
    """MCP identity guard counters (issuance, validation, rejection reasons)."""
    return {
        **MCP_IDENTITY_STATS,
        "replay_cache_size": len(MCP_IDENTITY_REPLAY_CACHE),
        "updated_at": datetime.now(UTC).isoformat(),
    }


# --- Tool Manifest Signing Endpoints ---

class SignManifestRequest(BaseModel):
    manifest: Dict[str, Any]

@app.post("/api/v2/tools/sign", tags=["Enterprise"])
async def sign_tool_manifest(req: SignManifestRequest):
    """Cryptographically sign a tool manifest."""
    signer = _get_manifest_signer()
    signed = signer.sign_manifest(req.manifest)
    return {
        "tool_name": signed.tool_name,
        "signature": signed.signature,
        "manifest_hash": signed.manifest_hash,
        "signed_at": signed.signed_at,
    }

class VerifyManifestRequest(BaseModel):
    tool_name: str
    manifest: Dict[str, Any]
    signature: str
    manifest_hash: str
    signed_at: str

@app.post("/api/v2/tools/verify", tags=["Enterprise"])
async def verify_tool_manifest(req: VerifyManifestRequest):
    """Verify a signed tool manifest's integrity."""
    from cognitive_firewall.tool_manifest_signer import SignedManifest
    signer = _get_manifest_signer()
    signed = SignedManifest(
        tool_name=req.tool_name,
        manifest=req.manifest,
        signature=req.signature,
        manifest_hash=req.manifest_hash,
        signed_at=req.signed_at,
    )
    result = signer.verify_manifest(signed)
    if result.valid:
        changed = signer.detect_rug_pull(req.tool_name, req.manifest)
        if changed:
            current_hash = hashlib.sha256(
                json.dumps(req.manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            _append_capped(
                MCP_RUGPULL_LOG,
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "tool_name": req.tool_name,
                    "change_type": "manifest_changed",
                    "original_hash": req.manifest_hash,
                    "current_hash": current_hash,
                    "reason": "Manifest differs from signed baseline",
                },
            )
    return {
        "valid": result.valid,
        "tool_name": result.tool_name,
        "reason": result.reason,
    }


# --- AIBOM Endpoints ---

class AIBOMRegisterRequest(BaseModel):
    component_id: str
    component_type: str
    version: str
    provider: str
    hash_value: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@app.post("/api/v2/aibom/register", tags=["Enterprise"])
async def register_aibom_component(req: AIBOMRegisterRequest):
    """Register a component in the AI Bill of Materials."""
    sc = _get_supply_chain()
    entry = sc.register_component(
        component_id=req.component_id,
        component_type=req.component_type,
        version=req.version,
        provider=req.provider,
        hash_value=req.hash_value,
        metadata=req.metadata,
    )
    return {
        "component_id": entry.component_id,
        "type": entry.component_type,
        "version": entry.version,
        "hash": entry.hash,
        "registered_at": entry.registered_at,
    }

class AIBOMVerifyRequest(BaseModel):
    component_id: str

@app.post("/api/v2/aibom/verify", tags=["Enterprise"])
async def verify_aibom_component(req: AIBOMVerifyRequest):
    """Verify a component's integrity."""
    sc = _get_supply_chain()
    result = sc.verify_component(req.component_id)
    return result

@app.get("/api/v2/aibom", tags=["Enterprise"])
async def get_aibom():
    """Get the full AI Bill of Materials."""
    sc = _get_supply_chain()
    return sc.generate_aibom()


@app.get("/api/v2/attestation/public_key", tags=["Enterprise"])
async def get_attestation_public_key():
    """Get the VerityFlux attestation public key."""
    key = _load_attestation_key()
    return {
        "key_id": key.get("key_id"),
        "public_key": key.get("public_key"),
        "created_at": key.get("created_at"),
    }


# =============================================================================
# UNIFIED EVALUATE ENDPOINT — Chains all cognitive firewall modules
# =============================================================================

class EvaluateActionRequest(BaseModel):
    """Full agent action evaluation — the single call an agent host makes."""
    agent_id: str
    session_id: Optional[str] = None
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    reasoning: Optional[str] = None
    original_goal: Optional[str] = None
    user_input: Optional[str] = None
    agent_response: Optional[str] = None
    memory_retrievals: Optional[List[Dict[str, Any]]] = None
    sandbox_attested: bool = False
    handoff_from_agent_id: Optional[str] = None
    handoff_channel: Optional[str] = None
    handoff_shared_reasoning: bool = False
    handoff_metadata: Optional[Dict[str, Any]] = None


@app.post("/api/v2/evaluate", tags=["Enterprise"])
async def evaluate_action(req: EvaluateActionRequest):
    """
    Unified agent action evaluation.

    Chains: adversarial scorer -> memory filter -> reasoning interceptor
    -> session drift tracker.  Returns a combined verdict with details from
    each module that ran.
    """
    verdict = {
        "action": "allow",
        "risk_score": 0.0,
        "modules_run": [],
        "details": {},
    }

    # 1. Adversarial scoring on user input
    if req.user_input:
        scorer = _get_adversarial_scorer()
        score_result = scorer.score_input(req.user_input)
        verdict["details"]["adversarial"] = {
            "hostility_score": score_result.hostility_score,
            "intent_class": score_result.intent_class,
            "is_adversarial": score_result.is_adversarial,
        }
        verdict["modules_run"].append("adversarial_scorer")
        if score_result.is_adversarial:
            verdict["risk_score"] = max(verdict["risk_score"], score_result.hostility_score * 100)

    # 2. Memory retrieval filtering
    if req.memory_retrievals:
        mf = _get_memory_filter()
        filter_result = mf.filter_retrievals(
            req.memory_retrievals,
            {
                "agent_id": req.agent_id,
                "session_id": req.session_id,
            },
        )
        verdict["details"]["memory_filter"] = {
            "removed_count": filter_result.removed_count,
            "modified_count": filter_result.modified_count,
            "threats_found": filter_result.threats_found,
            "cross_agent_alert": filter_result.cross_agent_alert,
            "cross_agent_findings": filter_result.cross_agent_findings,
        }
        verdict["modules_run"].append("memory_filter")
        if filter_result.threats_found:
            verdict["risk_score"] = max(verdict["risk_score"], 60.0)
        if filter_result.cross_agent_alert:
            verdict["risk_score"] = max(verdict["risk_score"], filter_result.risk_score)
        # Return cleaned retrievals for the caller to use
        verdict["cleaned_retrievals"] = filter_result.cleaned_retrievals

    # 3. Reasoning interception
    if req.reasoning:
        interceptor = _get_reasoning_interceptor()
        intercept_result = interceptor.intercept_reasoning(
            agent_id=req.agent_id,
            thinking_block=req.reasoning,
            original_goal=req.original_goal or "",
            handoff_from_agent_id=req.handoff_from_agent_id,
            handoff_channel=req.handoff_channel,
            handoff_shared_reasoning=req.handoff_shared_reasoning,
            handoff_metadata=req.handoff_metadata,
        )
        verdict["details"]["reasoning"] = {
            "action": intercept_result.action,
            "risk_score": intercept_result.risk_score,
            "violations": intercept_result.violations,
            "contamination_detected": intercept_result.contamination_detected,
            "contamination_findings": intercept_result.contamination_findings,
        }
        verdict["modules_run"].append("reasoning_interceptor")
        verdict["risk_score"] = max(verdict["risk_score"], intercept_result.risk_score)
        if intercept_result.contamination_detected:
            _emit_integration_event(
                event_type="REASONING_A2A_ALERT",
                agent_id=req.agent_id,
                status="CRITICAL" if intercept_result.action == "block" else "WARNING",
                reason="A2A chain-of-thought contamination detected in inherited reasoning",
                session_id=req.session_id,
                evidence={
                    "summary": "Inherited reasoning contained unsafe or unvalidated prior-agent control content",
                    "handoff_from_agent_id": req.handoff_from_agent_id,
                    "handoff_channel": req.handoff_channel,
                    "contamination_score": intercept_result.contamination_score,
                    "findings": intercept_result.contamination_findings,
                },
            )
        if intercept_result.action in ("block", "escalate"):
            verdict["action"] = intercept_result.action

    # 4. Tool call interception
    if req.tool_name:
        interceptor = _get_reasoning_interceptor()
        tool_result = interceptor.intercept_tool_call(
            agent_id=req.agent_id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            reasoning_context=req.reasoning,
            original_goal=req.original_goal,
        )
        verdict["details"]["tool_call"] = {
            "action": tool_result.action,
            "risk_score": tool_result.risk_score,
            "violations": tool_result.violations,
        }
        containment = _runtime_containment_checks(req.tool_name, req.arguments, sandbox_attested=req.sandbox_attested)
        verdict["details"]["containment"] = {
            "valid": containment.get("valid", True),
            "violations": containment.get("violations", []),
        }
        if not containment.get("valid", True):
            verdict["risk_score"] = max(verdict["risk_score"], 85.0)
            verdict["action"] = "block" if ENFORCEMENT_MODE == "enforce" else "escalate"
        verdict["modules_run"].append("tool_interceptor")
        verdict["risk_score"] = max(verdict["risk_score"], tool_result.risk_score)
        if tool_result.action in ("block", "escalate"):
            verdict["action"] = tool_result.action

    # 5. Session drift tracking
    if req.session_id and req.user_input and req.agent_response:
        tracker = _get_intent_tracker()
        track_result = tracker.track_interaction(
            session_id=req.session_id,
            agent_id=req.agent_id,
            user_input=req.user_input,
            agent_response=req.agent_response,
            tool_calls=[{"tool": req.tool_name, "args": req.arguments}] if req.tool_name else None,
        )
        verdict["details"]["session_drift"] = {
            "drift_score": track_result.drift_score,
            "is_crescendo": track_result.is_crescendo,
            "alert_level": track_result.alert_level,
        }
        verdict["modules_run"].append("session_drift_tracker")
        if track_result.is_crescendo:
            verdict["risk_score"] = max(verdict["risk_score"], 80.0)
            if verdict["action"] == "allow":
                verdict["action"] = "escalate"

    # Record to flight log so the UI can display it
    try:
        recorder = _get_flight_recorder()
        import json as _json
        from datetime import datetime as _dt
        log_entry = {
            "timestamp": _dt.now().isoformat(),
            "agent_id": req.agent_id,
            "tool_name": req.tool_name,
            "original_goal": req.original_goal or "",
            "firewall_decision": {
                "action": verdict["action"],
                "risk_score": verdict["risk_score"],
                "tier": "RUNTIME",
                "confidence": 1.0,
                "reasoning": "; ".join(
                    d.get("reasoning", d.get("action", ""))
                    for d in verdict["details"].values()
                    if isinstance(d, dict)
                ),
            },
            "enterprise_analysis": {
                "modules_run": verdict["modules_run"],
                "details": verdict["details"],
            },
            "reasoning_chain": [req.reasoning] if req.reasoning else [],
            "parameters": req.arguments,
            "context": {"session_id": req.session_id},
        }
        with open(recorder.session_file, "a") as _f:
            _f.write(_json.dumps(log_entry) + "\n")
    except Exception:
        pass  # Never let logging break the evaluate response

    # Also write to structured log for the second UI source
    try:
        from pathlib import Path as _P
        log_dir = _P(__file__).resolve().parents[2] / "logs"
        log_dir.mkdir(exist_ok=True)
        structured_entry = {
            "timestamp": _dt.now().isoformat(),
            "event_type": "firewall_decision",
            "agent_id": req.agent_id,
            "tool": req.tool_name,
            "decision": verdict["action"],
            "risk_score": verdict["risk_score"],
            "message": "; ".join(verdict["modules_run"]),
        }
        with open(log_dir / "verityflux.log", "a") as _f:
            _f.write(_json.dumps(structured_entry) + "\n")
    except Exception:
        pass

    _append_capped(ENFORCEMENT_LOG, {
        "timestamp": datetime.now(UTC).isoformat(),
        "module": "evaluate",
        "mode": ENFORCEMENT_MODE,
        "action": verdict.get("action"),
        "risk_score": verdict.get("risk_score", 0.0),
        "agent_id": req.agent_id,
        "tool_name": req.tool_name,
        "violations": [],
        "reasoning": ",".join(verdict.get("modules_run", [])),
    })

    if ATTESTATION_ENABLED:
        att_payload = {
            "attestation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": req.agent_id,
            "session_id": req.session_id,
            "tool_name": req.tool_name,
            "action": verdict.get("action"),
            "risk_score": verdict.get("risk_score", 0.0),
            "sandbox_attested": req.sandbox_attested,
        }
        sig = _sign_attestation(att_payload)
        attestation = {
            "key_id": sig["key_id"],
            "signature": sig["signature"],
            "hash": sig["hash"],
        }
        if ATTESTATION_INCLUDE_PUBLIC_KEY:
            attestation["public_key"] = sig["public_key"]
        if ATTESTATION_INCLUDE_PAYLOAD:
            attestation["payload"] = att_payload
        verdict["attestation"] = attestation
        _emit_integration_event(
            event_type="attestation_issued",
            agent_id=req.agent_id,
            status=verdict.get("action", "unknown"),
            evidence={
                "attestation_hash": sig["hash"],
                "attestation_key_id": sig["key_id"],
                "sandbox_attested": req.sandbox_attested,
            },
            reason="runtime_attestation",
            session_id=req.session_id,
            correlation_id=req.session_id,
        )

    return verdict


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    certfile = os.getenv("VERITYFLUX_TLS_CERTFILE") or os.getenv("TLS_CERTFILE")
    keyfile = os.getenv("VERITYFLUX_TLS_KEYFILE") or os.getenv("TLS_KEYFILE")
    ssl_kwargs = {}
    if certfile and keyfile:
        ssl_kwargs = {"ssl_certfile": certfile, "ssl_keyfile": keyfile}

    uvicorn.run(
        "api.v2.main:app",
        host="0.0.0.0",
        port=int(os.getenv("VERITYFLUX_PORT", "8003")),
        reload=True,
        log_level="info",
        **ssl_kwargs,
    )

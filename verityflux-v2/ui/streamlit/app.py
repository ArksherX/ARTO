#!/usr/bin/env python3
"""
VerityFlux Enterprise - Streamlit Web UI
Comprehensive Security Operations Dashboard

Features:
- Real-time SOC dashboard with threat level
- Security scanner interface
- Incident management
- Agent monitoring
- HITL approval queue
- Vulnerability database browser
- Integration configuration
- Analytics and reporting
"""

import streamlit as st
import os
import io
import csv
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta
import json
import asyncio
from typing import Optional, Dict, Any, List
import time
import urllib.request
import urllib.error
from glob import glob
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="VerityFlux Enterprise",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# CUSTOM CSS
# =============================================================================

st.markdown("""
<style>
    /* Main theme */
    .main {
        padding: 1rem;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
        border-radius: 10px;
        padding: 1.5rem;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        opacity: 0.8;
    }
    
    /* Threat level indicators */
    .threat-green { color: #00ff00; }
    .threat-yellow { color: #ffff00; }
    .threat-orange { color: #ff8c00; }
    .threat-red { color: #ff0000; }
    
    /* Status badges */
    .badge {
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    
    .badge-critical { background: #dc3545; color: white; }
    .badge-high { background: #fd7e14; color: white; }
    .badge-medium { background: #ffc107; color: black; }
    .badge-low { background: #17a2b8; color: white; }
    .badge-info { background: #6c757d; color: white; }
    
    /* Cards */
    .info-card {
        background: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 5px 5px 0;
    }
    
    /* Sidebar */
    .css-1d391kg {
        padding-top: 1rem;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #1e1e1e;
    }
    ::-webkit-scrollbar-thumb {
        background: #888;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================

def init_session_state():
    """Initialize session state variables"""
    default_vf_api_base = os.getenv("VERITYFLUX_API_BASE", "http://localhost:8003")
    default_vf_api_key = os.getenv("VERITYFLUX_API_KEY", "vf_admin_demo_key")
    default_vestigia_api_base = os.getenv("VESTIGIA_API_BASE", "http://localhost:8002")
    default_vestigia_api_key = os.getenv("VESTIGIA_API_KEY", "")

    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'organization' not in st.session_state:
        st.session_state.organization = None
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'dashboard'
    if 'api_base_url' not in st.session_state:
        st.session_state.api_base_url = default_vf_api_base
    if 'policy_cache' not in st.session_state:
        st.session_state.policy_cache = None
    if 'policy_cache_path' not in st.session_state:
        st.session_state.policy_cache_path = None
    if 'vf_api_key' not in st.session_state:
        st.session_state.vf_api_key = default_vf_api_key
    if 'vestigia_api_url' not in st.session_state:
        st.session_state.vestigia_api_url = default_vestigia_api_base
    if 'vestigia_api_key' not in st.session_state:
        st.session_state.vestigia_api_key = default_vestigia_api_key

init_session_state()

def _parse_timestamp(ts: Any) -> Optional[datetime]:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def _relative_time(dt: datetime) -> str:
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    secs = int(abs(delta.total_seconds()))
    if secs < 60:
        value, unit = secs, "s"
    elif secs < 3600:
        value, unit = secs // 60, "m"
    elif secs < 86400:
        value, unit = secs // 3600, "h"
    else:
        value, unit = secs // 86400, "d"
    suffix = "ago" if delta.total_seconds() >= 0 else "from now"
    return f"{value}{unit} {suffix}"


def format_timestamp(ts: Any) -> str:
    dt = _parse_timestamp(ts)
    if not dt:
        return str(ts) if ts not in (None, "") else "N/A"
    base = dt.strftime("%Y-%m-%d %H:%M:%S")
    zone = dt.tzname() or ("UTC" if dt.tzinfo else "local")
    return f"{base} {zone} ({_relative_time(dt)})"


# =============================================================================
# MOCK DATA GENERATORS (Replace with API calls in production)
# =============================================================================

def get_mock_metrics():
    """Generate mock SOC metrics"""
    return {
        "incidents": {
            "total": 47,
            "open": 12,
            "by_priority": {"p1_critical": 2, "p2_high": 5, "p3_medium": 8, "p4_low": 3},
            "by_status": {"open": 5, "acknowledged": 3, "investigating": 4, "resolved": 30, "closed": 5},
        },
        "sla": {
            "compliance_rate": 94.5,
            "avg_response_time_minutes": 8.3,
            "avg_resolution_time_hours": 4.2,
            "breaches": 3,
        },
        "events": {
            "total": 15420,
            "by_severity": {"critical": 23, "high": 156, "medium": 892, "low": 4521, "info": 9828},
            "blocked": 1245,
            "allowed": 13890,
            "approvals": 285,
        },
        "alerts": {
            "total": 342,
            "new": 18,
        },
        "agents": {
            "total": 24,
            "healthy": 21,
            "unhealthy": 2,
            "quarantined": 1,
        },
        "threat_level": "yellow",
    }


def get_mock_incidents():
    """Generate mock incidents"""
    return [
        {
            "id": "inc-001",
            "number": "INC-2026-00047",
            "title": "Critical Prompt Injection Detected",
            "priority": "p1_critical",
            "status": "investigating",
            "created_at": datetime.now() - timedelta(hours=2),
            "assigned_to": "analyst1",
            "affected_agents": ["customer-bot", "support-agent"],
        },
        {
            "id": "inc-002",
            "number": "INC-2026-00046",
            "title": "Unusual Data Access Pattern",
            "priority": "p2_high",
            "status": "acknowledged",
            "created_at": datetime.now() - timedelta(hours=5),
            "assigned_to": "analyst2",
            "affected_agents": ["data-analyzer"],
        },
        {
            "id": "inc-003",
            "number": "INC-2026-00045",
            "title": "Tool Misuse Attempt Blocked",
            "priority": "p3_medium",
            "status": "open",
            "created_at": datetime.now() - timedelta(hours=8),
            "assigned_to": None,
            "affected_agents": ["task-bot"],
        },
    ]


def get_mock_agents():
    """Generate mock agents"""
    return [
        {
            "id": "agent-001",
            "name": "customer-service-bot",
            "status": "healthy",
            "agent_type": "langchain",
            "model": "gpt-4o",
            "total_requests": 15420,
            "blocked_requests": 45,
            "health_score": 98.5,
            "last_seen": datetime.now() - timedelta(seconds=30),
        },
        {
            "id": "agent-002",
            "name": "data-analysis-agent",
            "status": "healthy",
            "agent_type": "llamaindex",
            "model": "claude-3-opus",
            "total_requests": 8932,
            "blocked_requests": 12,
            "health_score": 99.2,
            "last_seen": datetime.now() - timedelta(seconds=45),
        },
        {
            "id": "agent-003",
            "name": "code-review-bot",
            "status": "degraded",
            "agent_type": "custom",
            "model": "gpt-4-turbo",
            "total_requests": 3421,
            "blocked_requests": 89,
            "health_score": 72.1,
            "last_seen": datetime.now() - timedelta(minutes=5),
        },
        {
            "id": "agent-004",
            "name": "suspicious-agent",
            "status": "quarantined",
            "agent_type": "langchain",
            "model": "llama-3-70b",
            "total_requests": 892,
            "blocked_requests": 234,
            "health_score": 15.0,
            "last_seen": datetime.now() - timedelta(hours=2),
        },
    ]


# =============================================================================
# POLICY HELPERS (API-backed)
# =============================================================================

def api_get_policy(api_base_url: str, api_key: Optional[str]) -> Dict[str, Any]:
    """Fetch policy from API with compatibility fallback."""
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL"}
    endpoints = [f"{base}/api/v1/policy", f"{base}/policy"]
    last_error = None
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(endpoint)
            if api_key:
                req.add_header("X-API-Key", api_key)
                req.add_header("Authorization", f"Bearer {api_key}")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            data["ok"] = True
            data["_endpoint"] = endpoint
            return data
        except Exception as exc:
            last_error = str(exc)
    return {"ok": False, "error": f"Policy fetch failed: {last_error}"}


def api_update_policy(api_base_url: str, api_key: Optional[str], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Update policy via API."""
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL"}
    try:
        body = json.dumps({"policy": policy}).encode("utf-8")
        req = urllib.request.Request(
            f"{base}/api/v1/policy",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        data["ok"] = True
        return data
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def api_get_vestigia_policy_events(api_base_url: str, api_key: Optional[str], limit: int = 50) -> Optional[Dict[str, Any]]:
    """Fetch recent policy events from Vestigia."""
    try:
        url = f"{api_base_url}/events?limit={limit}"
        req = urllib.request.Request(url)
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        data["ok"] = True
        data["_source"] = "vestigia_api"
        return data
    except Exception as exc:
        # Fallback to shared suite audit log when Vestigia API is unavailable.
        shared_log = os.getenv(
            "SUITE_AUDIT_LOG",
            str(Path(__file__).resolve().parents[3] / "shared_state" / "shared_audit.log"),
        )
        try:
            events = []
            if Path(shared_log).exists():
                with open(shared_log, "r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        line = raw.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) < 3:
                            continue
                        action_type = str(parts[2]).strip()
                        action_norm = action_type.lower()
                        if action_norm not in {"policy_updated", "policy_reloaded"}:
                            continue
                        status = "INFO"
                        summary = ""
                        for part in parts[3:]:
                            pl = part.lower()
                            if pl.startswith("status:"):
                                status = part.split(":", 1)[1].strip()
                            else:
                                summary = (summary + " | " + part).strip(" |")
                        events.append({
                            "timestamp": parts[0],
                            "actor_id": parts[1],
                            "action_type": action_type,
                            "status": status,
                            "evidence": {"summary": summary},
                        })
            events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
            return {
                "ok": True,
                "_source": "shared_log_fallback",
                "_fallback_error": str(exc),
                "events": events[:limit],
            }
        except Exception as shared_exc:
            return {"ok": False, "error": str(exc), "fallback_error": str(shared_exc)}


def api_start_scan(api_base_url: str, api_key: Optional[str], payload: Dict[str, Any]) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL"}
    try:
        req = urllib.request.Request(
            f"{base}/api/v1/scans",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        data["ok"] = True
        return data
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def api_list_scans(api_base_url: str, api_key: Optional[str], limit: int = 20) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL", "items": []}
    try:
        req = urllib.request.Request(f"{base}/api/v1/scans?limit={int(limit)}")
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"ok": True, "items": data.get("items", []), "total": data.get("total", 0)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "items": []}


def api_get_scan_progress(api_base_url: str, api_key: Optional[str], scan_id: str) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    try:
        req = urllib.request.Request(f"{base}/api/v1/scans/{scan_id}/progress")
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        data["ok"] = True
        return data
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def api_get_scan_findings(api_base_url: str, api_key: Optional[str], scan_id: str) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    try:
        req = urllib.request.Request(f"{base}/api/v1/scans/{scan_id}/findings")
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"ok": True, "items": data if isinstance(data, list) else []}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "items": []}


def api_register_agent(api_base_url: str, api_key: Optional[str], payload: Dict[str, Any]) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL"}
    try:
        req = urllib.request.Request(
            f"{base}/api/v1/soc/agents",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"ok": True, "item": data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def api_list_agents(api_base_url: str, api_key: Optional[str], limit: int = 200, status: Optional[str] = None) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL", "items": []}
    try:
        query = f"limit={int(limit)}"
        if status:
            query += f"&status={status}"
        req = urllib.request.Request(f"{base}/api/v1/soc/agents?{query}")
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"ok": True, "items": data.get("items", []), "total": data.get("total", 0)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "items": []}


def api_quarantine_agent(api_base_url: str, api_key: Optional[str], agent_id: str, reason: str) -> Dict[str, Any]:
    base = (api_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "Missing API base URL"}
    try:
        req = urllib.request.Request(
            f"{base}/api/v1/soc/agents/{agent_id}/quarantine",
            data=json.dumps({"reason": reason}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if api_key:
            req.add_header("X-API-Key", api_key)
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"ok": True, "item": data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def parse_agents_upload(uploaded_file) -> List[Dict[str, Any]]:
    name = (uploaded_file.name or "").lower()
    raw = uploaded_file.getvalue()
    rows: List[Dict[str, Any]] = []
    if name.endswith(".json"):
        parsed = json.loads(raw.decode("utf-8"))
        if isinstance(parsed, dict):
            parsed = parsed.get("agents", [])
        if not isinstance(parsed, list):
            raise ValueError("JSON must be a list or {'agents': [...]} format.")
        rows = parsed
    elif name.endswith(".csv"):
        text = raw.decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
    else:
        raise ValueError("Unsupported file type; use .json or .csv")

    normalized = []
    for i, row in enumerate(rows, start=1):
        name = str(row.get("name", "")).strip()
        agent_type = str(row.get("agent_type", "")).strip()
        if not name or not agent_type:
            raise ValueError(f"Row {i}: 'name' and 'agent_type' are required.")
        tools = row.get("tools", [])
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        normalized.append({
            "name": name,
            "agent_type": agent_type,
            "model_provider": str(row.get("model_provider", "")).strip() or None,
            "model_name": str(row.get("model_name", "")).strip() or None,
            "tools": tools if isinstance(tools, list) else [],
            "environment": str(row.get("environment", "production")).strip() or "production",
        })
    return normalized


def resolve_tessera_registry_path() -> Path:
    env = os.getenv("TESSERA_REGISTRY_PATH")
    if env:
        return Path(env)
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "tessera" / "data" / "tessera_registry.json"


def load_tessera_registry_agents() -> Dict[str, Any]:
    path = resolve_tessera_registry_path()
    if not path.exists():
        return {"ok": False, "error": f"Registry not found: {path}", "items": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {"ok": False, "error": "Tessera registry format invalid", "items": []}
        items: List[Dict[str, Any]] = []
        for agent_id, row in raw.items():
            if not isinstance(row, dict):
                continue
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            allowed_tools = row.get("allowed_tools", [])
            if isinstance(allowed_tools, str):
                allowed_tools = [t.strip() for t in allowed_tools.split(",") if t.strip()]
            payload = {
                "name": str(row.get("agent_id") or agent_id),
                "agent_type": str(metadata.get("framework") or "tessera_agent"),
                "model_provider": metadata.get("model_provider"),
                "model_name": metadata.get("model_name"),
                "tools": allowed_tools if isinstance(allowed_tools, list) else [],
                "environment": str(metadata.get("environment") or "production"),
                "_source_status": str(row.get("status", "active")),
                "_source_owner": str(row.get("owner", "")),
                "_source_tenant": str(row.get("tenant_id", "default")),
            }
            items.append(payload)
        return {"ok": True, "items": items, "path": str(path)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "items": [], "path": str(path)}


def get_vulnerability_catalog() -> List[Dict[str, Any]]:
    """Research-oriented vulnerability reference catalog."""
    llm_top_10 = [
        ("LLM01", "Prompt Injection", "critical"),
        ("LLM02", "Insecure Output Handling", "high"),
        ("LLM03", "Training Data Poisoning", "high"),
        ("LLM04", "Model Denial of Service", "medium"),
        ("LLM05", "Supply Chain Vulnerabilities", "high"),
        ("LLM06", "Sensitive Information Disclosure", "high"),
        ("LLM07", "Insecure Plugin Design", "high"),
        ("LLM08", "Excessive Agency", "critical"),
        ("LLM09", "Overreliance", "medium"),
        ("LLM10", "Model Theft", "high"),
    ]
    agentic_top_10 = [
        ("ASI01", "Agent Goal Hijacking", "critical"),
        ("ASI02", "Tool Misuse and Exploitation", "critical"),
        ("ASI03", "Memory Poisoning", "high"),
        ("ASI04", "Planning/Reasoning Manipulation", "high"),
        ("ASI05", "Unexpected Code Execution", "critical"),
        ("ASI06", "Autonomous Privilege Escalation", "critical"),
        ("ASI07", "Unsafe Multi-Agent Interaction", "high"),
        ("ASI08", "Insecure Human-in-the-Loop Bypass", "high"),
        ("ASI09", "Data Exfiltration via Agent Workflow", "critical"),
        ("ASI10", "Policy Evasion by Context Chaining", "high"),
    ]

    catalog: List[Dict[str, Any]] = []
    for vuln_id, title, severity in llm_top_10:
        default_cvss = {"critical": 9.5, "high": 8.2, "medium": 6.4, "low": 3.9}.get(severity, 5.0)
        catalog.append({
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "cvss": default_cvss,
            "source": "OWASP LLM Top 10 (2025)",
            "description": f"{title} can cause unsafe model behavior or policy bypass if not constrained.",
            "technical_impact": "Policy circumvention, unsafe tool invocation, data leakage, or model abuse.",
            "business_impact": "Incident response cost, compliance risk, and loss of trust in AI-enabled workflows.",
            "recommendations": [
                "Add strict input/output validation and policy constraints.",
                "Apply runtime risk scoring and high-risk approval workflow.",
                "Emit auditable evidence for every enforcement decision.",
            ],
        })
    for vuln_id, title, severity in agentic_top_10:
        default_cvss = {"critical": 9.6, "high": 8.3, "medium": 6.5, "low": 4.0}.get(severity, 5.0)
        catalog.append({
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "cvss": default_cvss,
            "source": "OWASP Agentic Top 10 (2025)",
            "description": f"{title} targets autonomous decision/execution pathways in agentic systems.",
            "technical_impact": "Unintended autonomous behavior, lateral movement, privileged action misuse.",
            "business_impact": "Operational disruption, unauthorized actions, and governance/control failures.",
            "recommendations": [
                "Constrain tool capabilities and enforce least privilege per agent.",
                "Use runtime cognitive firewall decisions with block/approval modes.",
                "Correlate identity + verification + audit evidence for reconstruction.",
            ],
        })
    return catalog


def get_vulnerability_catalog_map() -> Dict[str, Dict[str, Any]]:
    return {item["vuln_id"]: item for item in get_vulnerability_catalog()}


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Merge scan finding with catalog-level context."""
    vuln_id = finding.get("vuln_id", "")
    catalog = get_vulnerability_catalog_map().get(vuln_id, {})
    target = finding.get("target_name", "unknown-target")
    component = finding.get("component", "agent-runtime")
    return {
        **finding,
        "owasp_source": catalog.get("source", "Unknown"),
        "description": finding.get("description") or catalog.get("description", "No description available."),
        "technical_impact": catalog.get("technical_impact", "Risk to runtime integrity and policy conformance."),
        "business_impact": catalog.get("business_impact", "Potential operational/compliance impact."),
        "recommendations": finding.get("recommendation") or "; ".join(catalog.get("recommendations", [])),
        "affected_feature": f"{target}:{component}",
    }


def get_mock_approvals():
    """Generate mock approval requests"""
    return [
        {
            "id": "apr-001",
            "title": "Execute database query",
            "agent": "data-analysis-agent",
            "tool": "sql_executor",
            "risk_score": 75,
            "risk_level": "high",
            "created_at": datetime.now() - timedelta(minutes=5),
            "expires_at": datetime.now() + timedelta(minutes=25),
            "status": "pending",
        },
        {
            "id": "apr-002",
            "title": "Send email to external recipient",
            "agent": "customer-service-bot",
            "tool": "email_sender",
            "risk_score": 62,
            "risk_level": "medium",
            "created_at": datetime.now() - timedelta(minutes=12),
            "expires_at": datetime.now() + timedelta(minutes=18),
            "status": "pending",
        },
        {
            "id": "apr-003",
            "title": "Access sensitive file",
            "agent": "code-review-bot",
            "tool": "file_reader",
            "risk_score": 88,
            "risk_level": "critical",
            "created_at": datetime.now() - timedelta(minutes=2),
            "expires_at": datetime.now() + timedelta(minutes=13),
            "status": "pending",
        },
    ]


def get_mock_vulnerabilities():
    """Generate mock vulnerability list"""
    return [
        {"vuln_id": "LLM01", "title": "Prompt Injection", "severity": "critical", "cvss": 9.8, "source": "OWASP LLM"},
        {"vuln_id": "LLM02", "title": "Sensitive Information Disclosure", "severity": "high", "cvss": 8.5, "source": "OWASP LLM"},
        {"vuln_id": "ASI01", "title": "Agent Goal Hijacking", "severity": "critical", "cvss": 9.9, "source": "OWASP Agentic"},
        {"vuln_id": "ASI02", "title": "Tool Misuse and Exploitation", "severity": "critical", "cvss": 9.5, "source": "OWASP Agentic"},
        {"vuln_id": "ASI05", "title": "Unexpected Code Execution", "severity": "critical", "cvss": 9.8, "source": "OWASP Agentic"},
        {"vuln_id": "LLM05", "title": "Improper Output Handling", "severity": "high", "cvss": 8.8, "source": "OWASP LLM"},
        {"vuln_id": "LLM07", "title": "System Prompt Leakage", "severity": "medium", "cvss": 6.5, "source": "OWASP LLM"},
    ]


def get_mock_scan_history():
    """Generate mock scan history"""
    return [
        {
            "scan_id": "scan-001",
            "target": "Production GPT-4 Agent",
            "status": "completed",
            "profile": "standard",
            "risk_score": 65,
            "findings": {"critical": 1, "high": 3, "medium": 5, "low": 2},
            "started_at": datetime.now() - timedelta(hours=4),
            "duration_minutes": 12,
        },
        {
            "scan_id": "scan-002",
            "target": "Data Analysis Bot",
            "status": "completed",
            "profile": "deep",
            "risk_score": 35,
            "findings": {"critical": 0, "high": 1, "medium": 3, "low": 4},
            "started_at": datetime.now() - timedelta(days=1),
            "duration_minutes": 28,
        },
        {
            "scan_id": "scan-003",
            "target": "Customer Service Agent",
            "status": "running",
            "profile": "quick",
            "risk_score": None,
            "findings": {},
            "started_at": datetime.now() - timedelta(minutes=3),
            "duration_minutes": None,
        },
    ]


def get_firewall_activity(limit: int = 200) -> List[Dict[str, Any]]:
    """Load runtime cognitive firewall activity from local logs."""
    activity: List[Dict[str, Any]] = []
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    for fp in glob(os.path.join(base_dir, "flight_logs", "*.jsonl")):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    decision = obj.get("firewall_decision", {})
                    activity.append({
                        "timestamp": obj.get("timestamp"),
                        "source": "flight_recorder",
                        "agent_id": obj.get("agent_state", {}).get("agent_id"),
                        "tool": obj.get("agent_state", {}).get("tool_name"),
                        "decision": decision.get("action"),
                        "risk_score": decision.get("risk_score"),
                        "reasoning": decision.get("reasoning"),
                    })
        except Exception:
            continue

    log_path = os.path.join(base_dir, "logs", "verityflux.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if obj.get("event_type") != "firewall_decision":
                        continue
                    activity.append({
                        "timestamp": obj.get("timestamp"),
                        "source": "structured_log",
                        "agent_id": obj.get("agent_id"),
                        "tool": obj.get("tool"),
                        "decision": obj.get("decision"),
                        "risk_score": obj.get("risk_score"),
                        "reasoning": obj.get("message"),
                    })
        except Exception:
            pass

    activity.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return activity[:limit]


# =============================================================================
# UI COMPONENTS
# =============================================================================

def render_threat_level_indicator(level: str):
    """Render threat level indicator"""
    colors = {
        "green": ("#00ff00", "LOW"),
        "yellow": ("#ffff00", "ELEVATED"),
        "orange": ("#ff8c00", "HIGH"),
        "red": ("#ff0000", "CRITICAL"),
    }
    
    color, label = colors.get(level, ("#6c757d", "UNKNOWN"))
    
    st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: #1e1e1e; border-radius: 10px; border: 2px solid {color};">
            <div style="font-size: 0.9rem; color: #888;">THREAT LEVEL</div>
            <div style="font-size: 2rem; font-weight: bold; color: {color}; text-shadow: 0 0 10px {color};">
                ● {label}
            </div>
        </div>
    """, unsafe_allow_html=True)


def render_metric_card(value, label, delta=None, delta_color="normal"):
    """Render a metric card"""
    delta_html = ""
    if delta is not None:
        delta_color_code = "#00ff00" if delta_color == "good" else "#ff0000" if delta_color == "bad" else "#888"
        delta_sign = "+" if delta > 0 else ""
        delta_html = f'<div style="color: {delta_color_code}; font-size: 0.9rem;">{delta_sign}{delta}%</div>'
    
    st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            {delta_html}
        </div>
    """, unsafe_allow_html=True)


def render_severity_badge(severity: str):
    """Render severity badge"""
    colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }
    text_colors = {
        "critical": "white",
        "high": "white",
        "medium": "black",
        "low": "white",
        "info": "white",
    }
    
    color = colors.get(severity.lower(), "#6c757d")
    text_color = text_colors.get(severity.lower(), "white")
    
    return f'<span style="background: {color}; color: {text_color}; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; font-weight: 600;">{severity.upper()}</span>'


def render_status_badge(status: str):
    """Render status badge"""
    colors = {
        "healthy": "#28a745",
        "degraded": "#ffc107",
        "unhealthy": "#fd7e14",
        "offline": "#6c757d",
        "quarantined": "#dc3545",
        "open": "#17a2b8",
        "acknowledged": "#ffc107",
        "investigating": "#fd7e14",
        "resolved": "#28a745",
        "closed": "#6c757d",
        "pending": "#17a2b8",
        "approved": "#28a745",
        "denied": "#dc3545",
        "running": "#17a2b8",
        "completed": "#28a745",
        "failed": "#dc3545",
    }
    
    color = colors.get(status.lower(), "#6c757d")
    
    return f'<span style="background: {color}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; font-weight: 600;">{status.upper()}</span>'


# =============================================================================
# PAGE: SOC DASHBOARD
# =============================================================================

def page_dashboard():
    """Main SOC Dashboard"""
    st.title("🛡️ SOC Command Center")
    
    # Get metrics
    metrics = get_mock_metrics()
    
    # Threat level and key metrics row
    col1, col2, col3, col4, col5 = st.columns([1.5, 1, 1, 1, 1])
    
    with col1:
        render_threat_level_indicator(metrics["threat_level"])
    
    with col2:
        st.metric("Open Incidents", metrics["incidents"]["open"], delta="-2", delta_color="normal")
    
    with col3:
        st.metric("Active Alerts", metrics["alerts"]["new"], delta="+5")
    
    with col4:
        st.metric("SLA Compliance", f"{metrics['sla']['compliance_rate']}%", delta="+1.2%")
    
    with col5:
        st.metric("Agents Online", f"{metrics['agents']['healthy']}/{metrics['agents']['total']}")
    
    st.divider()

    st.subheader("🔗 Live Integration (Policy + Audit)")
    col_live1, col_live2 = st.columns(2)

    with col_live1:
        if st.button("Load Current Policy", key="dash_load_policy"):
            result = api_get_policy(st.session_state.api_base_url, st.session_state.vf_api_key)
            if result.get("ok"):
                st.session_state.policy_cache = result.get("policy", {})
                st.success("Policy loaded from API.")
            else:
                st.error(f"Failed to load policy from API: {result.get('error', 'unknown error')}")
        if st.session_state.policy_cache is not None:
            st.json(st.session_state.policy_cache)

    with col_live2:
        if st.button("Load Policy Audit Events", key="dash_load_policy_events"):
            audit = api_get_vestigia_policy_events(
                st.session_state.vestigia_api_url,
                st.session_state.vestigia_api_key,
                limit=20,
            )
            if audit and isinstance(audit, dict) and audit.get("ok"):
                st.session_state.policy_audit = audit.get("events", [])
                if audit.get("_source") == "shared_log_fallback":
                    st.warning("Vestigia API unavailable; showing policy events from shared audit log fallback.")
            else:
                st.session_state.policy_audit = []
                st.error(f"Failed to load audit events from Vestigia: {(audit or {}).get('error', 'unknown error')}")
        events = st.session_state.get("policy_audit", [])
        policy_events = [
            e for e in events
            if str(e.get("action_type", "")).lower() in ("policy_updated", "policy_reloaded")
        ]
        if policy_events:
            st.dataframe(pd.DataFrame([{
                "timestamp": e.get("timestamp"),
                "action": e.get("action_type"),
                "actor": e.get("actor_id"),
                "status": e.get("status"),
            } for e in policy_events]), use_container_width=True)
        else:
            st.caption("No policy events loaded yet.")
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Events by Severity (24h)")
        
        events_data = metrics["events"]["by_severity"]
        fig = go.Figure(data=[
            go.Bar(
                x=list(events_data.keys()),
                y=list(events_data.values()),
                marker_color=['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'],
            )
        ])
        fig.update_layout(
            height=300,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor='#333'),
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Incidents by Priority")
        
        priority_data = metrics["incidents"]["by_priority"]
        fig = go.Figure(data=[
            go.Pie(
                labels=['Critical (P1)', 'High (P2)', 'Medium (P3)', 'Low (P4)'],
                values=[
                    priority_data.get("p1_critical", 0),
                    priority_data.get("p2_high", 0),
                    priority_data.get("p3_medium", 0),
                    priority_data.get("p4_low", 0),
                ],
                hole=0.4,
                marker_colors=['#dc3545', '#fd7e14', '#ffc107', '#17a2b8'],
            )
        ])
        fig.update_layout(
            height=300,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent activity
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🚨 Recent Incidents")
        
        incidents = get_mock_incidents()
        for incident in incidents[:5]:
            priority_color = {
                "p1_critical": "🔴",
                "p2_high": "🟠",
                "p3_medium": "🟡",
                "p4_low": "🔵",
            }.get(incident["priority"], "⚪")
            
            with st.container():
                st.markdown(f"""
                    <div style="background: #1e1e1e; padding: 0.75rem; border-radius: 5px; margin-bottom: 0.5rem; border-left: 3px solid {'#dc3545' if 'critical' in incident['priority'] else '#fd7e14' if 'high' in incident['priority'] else '#ffc107'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>{priority_color} <strong>{incident['number']}</strong></span>
                            {render_status_badge(incident['status'])}
                        </div>
                        <div style="color: #ccc; font-size: 0.9rem; margin-top: 0.25rem;">{incident['title']}</div>
                        <div style="color: #888; font-size: 0.8rem; margin-top: 0.25rem;">
                            Assigned: {incident['assigned_to'] or 'Unassigned'} | {incident['created_at'].strftime('%H:%M')}
                        </div>
                    </div>
                """, unsafe_allow_html=True)
    
    with col2:
        st.subheader("⏳ Pending Approvals")
        
        approvals = get_mock_approvals()
        for approval in approvals[:5]:
            time_remaining = (approval["expires_at"] - datetime.now()).total_seconds() / 60
            urgency_color = "#dc3545" if time_remaining < 10 else "#ffc107" if time_remaining < 20 else "#28a745"
            
            with st.container():
                st.markdown(f"""
                    <div style="background: #1e1e1e; padding: 0.75rem; border-radius: 5px; margin-bottom: 0.5rem; border-left: 3px solid {urgency_color};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span><strong>{approval['agent']}</strong></span>
                            {render_severity_badge(approval['risk_level'])}
                        </div>
                        <div style="color: #ccc; font-size: 0.9rem; margin-top: 0.25rem;">{approval['title']}</div>
                        <div style="color: #888; font-size: 0.8rem; margin-top: 0.25rem;">
                            Tool: {approval['tool']} | Risk: {approval['risk_score']}% | ⏱️ {int(time_remaining)}m remaining
                        </div>
                    </div>
                """, unsafe_allow_html=True)
    
    # Agent status
    st.subheader("🤖 Agent Status")
    
    agents = get_mock_agents()
    
    cols = st.columns(4)
    for i, agent in enumerate(agents):
        with cols[i % 4]:
            status_color = {
                "healthy": "#28a745",
                "degraded": "#ffc107",
                "unhealthy": "#fd7e14",
                "quarantined": "#dc3545",
                "offline": "#6c757d",
            }.get(agent["status"], "#6c757d")
            
            st.markdown(f"""
                <div style="background: #1e1e1e; padding: 1rem; border-radius: 8px; border-top: 3px solid {status_color};">
                    <div style="font-weight: bold; color: white;">{agent['name']}</div>
                    <div style="color: #888; font-size: 0.8rem;">{agent['agent_type']} • {agent['model']}</div>
                    <div style="margin-top: 0.5rem;">
                        {render_status_badge(agent['status'])}
                    </div>
                    <div style="color: #ccc; font-size: 0.85rem; margin-top: 0.5rem;">
                        Health: {agent['health_score']}% | Blocked: {agent['blocked_requests']}
                    </div>
                </div>
            """, unsafe_allow_html=True)


# =============================================================================
# PAGE: SECURITY SCANNER
# =============================================================================

def page_scanner():
    """Security Scanner Interface"""
    st.title("🔍 Security Scanner")
    
    tab1, tab2, tab3 = st.tabs(["New Scan", "Scan History", "Findings"])
    
    with tab1:
        st.subheader("Configure New Scan")
        
        col1, col2 = st.columns(2)
        
        with col1:
            target_type = st.selectbox(
                "Target Type",
                ["OpenAI", "Anthropic", "Ollama", "Hugging Face", "Azure OpenAI", "Custom API"]
            )
            
            target_name = st.text_input("Target Name", placeholder="Production GPT-4 Agent")
            
            if target_type == "OpenAI":
                api_key = st.text_input("API Key", type="password", placeholder="sk-...")
                model = st.selectbox("Model", ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini", "gpt-3.5-turbo"])
            elif target_type == "Anthropic":
                api_key = st.text_input("API Key", type="password", placeholder="sk-ant-...")
                model = st.selectbox("Model", ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"])
            elif target_type == "Ollama":
                endpoint = st.text_input("Endpoint URL", value="http://localhost:11434")
                model = st.text_input("Model Name", placeholder="llama2")
            elif target_type == "Hugging Face":
                endpoint = st.text_input("Endpoint URL", placeholder="https://api-inference.huggingface.co/models/<model>")
                api_key = st.text_input("HF Token", type="password", placeholder="hf_...")
                model = st.text_input("Model Name", placeholder="meta-llama/Llama-3.1-8B-Instruct")
            else:
                endpoint = st.text_input("Endpoint URL", placeholder="https://api.example.com/v1/chat")
                api_key = st.text_input("API Key", type="password")
        
        with col2:
            scan_profile = st.selectbox(
                "Scan Profile",
                ["Quick (~2 min)", "Standard (~10 min)", "Deep (~30 min)", "Compliance"],
                index=1
            )
            
            st.write("**Profile Details:**")
            profile_info = {
                "Quick (~2 min)": "Tests top 5 critical vulnerabilities (LLM01, LLM02, ASI01, ASI02, ASI05)",
                "Standard (~10 min)": "Tests all OWASP LLM Top 10 + Agentic Top 10",
                "Deep (~30 min)": "Full test suite + fuzzing variations + edge cases",
                "Compliance": "Standard tests + SOC2/GDPR compliance mapping",
            }
            st.info(profile_info.get(scan_profile, ""))
            
            include_vulns = st.multiselect(
                "Include Specific Vulnerabilities (optional)",
                ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
                 "ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]
            )
            
            exclude_vulns = st.multiselect(
                "Exclude Vulnerabilities (optional)",
                ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
                 "ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]
            )
        
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            if not target_name:
                st.error("Target Name is required.")
            elif target_type == "Ollama" and (not endpoint or not model):
                st.error("For Ollama, Endpoint URL and Model Name are required.")
            elif target_type == "Hugging Face" and (not endpoint or not model):
                st.error("For Hugging Face, Endpoint URL and Model Name are required.")
            else:
                provider_map = {
                    "OpenAI": "openai",
                    "Anthropic": "anthropic",
                    "Ollama": "ollama",
                    "Hugging Face": "huggingface",
                    "Azure OpenAI": "azure_openai",
                    "Custom API": "custom_api",
                }
                payload = {
                    "target": {
                        "target_type": provider_map.get(target_type, target_type.lower().replace(" ", "_")),
                        "name": target_name,
                        "endpoint_url": endpoint if target_type in ("Ollama", "Hugging Face", "Custom API", "Azure OpenAI") else None,
                        "model_name": model if target_type in ("OpenAI", "Anthropic", "Ollama", "Hugging Face", "Azure OpenAI") else "",
                        "credentials": {"api_key": api_key} if target_type in ("OpenAI", "Anthropic", "Hugging Face", "Custom API", "Azure OpenAI") and api_key else {},
                        "config": {"provider_ui": target_type},
                    },
                    "config": {
                        "profile": scan_profile.split(" ")[0].lower(),
                        "include_vulns": include_vulns,
                        "exclude_vulns": exclude_vulns,
                    },
                }
                with st.spinner("Initializing scan via API..."):
                    started = api_start_scan(st.session_state.api_base_url, st.session_state.vf_api_key, payload)
                if started.get("ok"):
                    st.success(f"✅ Scan started! ID: {started.get('scan_id')}")
                    st.session_state.last_scan_id = started.get("scan_id")
                    st.info("Navigate to Scan History tab to monitor real progress.")
                else:
                    st.error(f"Failed to start scan: {started.get('error', 'unknown error')}")
    
    with tab2:
        st.subheader("Scan History")

        fetched = api_list_scans(st.session_state.api_base_url, st.session_state.vf_api_key, limit=50)
        scans = fetched.get("items", [])
        if not scans:
            if fetched.get("ok"):
                st.info("No API scans yet. Start one from the New Scan tab.")
            else:
                st.error(f"Unable to load scan history: {fetched.get('error', 'unknown error')}")
        else:
            for scan in scans:
                status = str(scan.get("status", "unknown")).lower()
                with st.expander(f"🔍 {scan.get('target_name', 'unknown')} - {status.upper()}", expanded=(status == 'running')):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Status", status.upper())
                    with col2:
                        st.metric("Profile", str(scan.get('profile', 'standard')).capitalize())
                    with col3:
                        risk = scan.get("overall_risk_score")
                        st.metric("Risk Score", f"{int(risk) if risk is not None else '...'}/100")
                    with col4:
                        started_at = scan.get("started_at")
                        completed_at = scan.get("completed_at")
                        st.metric("Started", format_timestamp(started_at) if started_at else "...")
                        if completed_at:
                            st.caption(f"Completed: {format_timestamp(completed_at)}")

                    if status in ("running", "initializing"):
                        prog = api_get_scan_progress(st.session_state.api_base_url, st.session_state.vf_api_key, scan.get("scan_id"))
                        pct = float(prog.get("progress_percent", 0)) if prog.get("ok") else 0.0
                        st.progress(pct / 100.0, text=f"Status: {status.upper()} | {int(pct)}%")

                    findings_summary = scan.get("findings_summary") or {}
                    if findings_summary:
                        st.write("**Findings Summary:**")
                        findings_df = pd.DataFrame([
                            {"Severity": "Critical", "Count": findings_summary.get('critical', 0)},
                            {"Severity": "High", "Count": findings_summary.get('high', 0)},
                            {"Severity": "Medium", "Count": findings_summary.get('medium', 0)},
                            {"Severity": "Low", "Count": findings_summary.get('low', 0)},
                        ])
                        st.dataframe(findings_df, use_container_width=True, hide_index=True)
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.caption(f"Scan ID: {scan.get('scan_id')}")
                    with col2:
                        found = api_get_scan_findings(st.session_state.api_base_url, st.session_state.vf_api_key, scan.get("scan_id"))
                        if found.get("ok"):
                            st.caption(f"Findings: {len(found.get('items', []))}")
                            raw_findings = found.get("items", [])
                            enriched_findings = [enrich_finding(f) for f in raw_findings]
                            if enriched_findings:
                                st.markdown("**Detailed Findings:**")
                                detail_df = pd.DataFrame([{
                                    "vuln_id": f.get("vuln_id"),
                                    "title": f.get("title"),
                                    "severity": str(f.get("severity", "")).upper(),
                                    "risk_score": f.get("risk_score"),
                                    "affected_feature": f.get("affected_feature"),
                                    "owasp_source": f.get("owasp_source"),
                                    "status": f.get("status"),
                                } for f in enriched_findings])
                                st.dataframe(detail_df, use_container_width=True, hide_index=True)

                                for idx, f in enumerate(enriched_findings, start=1):
                                    with st.expander(f"[{f.get('vuln_id')}] {f.get('title')} - {str(f.get('severity','')).upper()}"):
                                        st.markdown(f"**Affected Endpoint/Feature:** `{f.get('affected_feature')}`")
                                        st.markdown(f"**OWASP Mapping:** `{f.get('owasp_source')}`")
                                        st.markdown(f"**Description:** {f.get('description')}")
                                        st.markdown(f"**Technical Impact:** {f.get('technical_impact')}")
                                        st.markdown(f"**Business Impact:** {f.get('business_impact')}")
                                        st.markdown(f"**Recommendations:** {f.get('recommendations')}")
                                        payload = f.get("test_payload")
                                        response = f.get("response_snippet")
                                        if payload:
                                            st.markdown("**Test Payload:**")
                                            st.code(str(payload), language="text")
                                        if response:
                                            st.markdown("**Response Snippet:**")
                                            st.code(str(response), language="text")
                    with col3:
                        if status == 'failed':
                            st.error(scan.get("error", "Scan failed"))
    
    with tab3:
        st.subheader("All Findings")
        
        # Mock findings
        findings = [
            {"vuln_id": "LLM01", "title": "Direct Instruction Override", "severity": "critical", "target": "Production GPT-4", "status": "confirmed"},
            {"vuln_id": "LLM01", "title": "Role Playing Jailbreak", "severity": "critical", "target": "Production GPT-4", "status": "potential"},
            {"vuln_id": "LLM07", "title": "System Prompt Leakage", "severity": "medium", "target": "Production GPT-4", "status": "confirmed"},
            {"vuln_id": "ASI02", "title": "SQL Tool Abuse", "severity": "high", "target": "Data Analysis Bot", "status": "potential"},
        ]
        
        severity_filter = st.multiselect("Filter by Severity", ["critical", "high", "medium", "low"], default=["critical", "high"])
        
        for finding in findings:
            if finding['severity'] in severity_filter:
                st.markdown(f"""
                    <div style="background: #1e1e1e; padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; border-left: 4px solid {'#dc3545' if finding['severity'] == 'critical' else '#fd7e14' if finding['severity'] == 'high' else '#ffc107'};">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span><strong>[{finding['vuln_id']}]</strong> {finding['title']}</span>
                            {render_severity_badge(finding['severity'])}
                        </div>
                        <div style="color: #888; font-size: 0.85rem; margin-top: 0.5rem;">
                            Target: {finding['target']} | Status: {finding['status'].capitalize()}
                        </div>
                    </div>
                """, unsafe_allow_html=True)


# =============================================================================
# PAGE: INCIDENTS
# =============================================================================

def page_incidents():
    """Incident Management"""
    st.title("🚨 Incident Management")
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        status_filter = st.selectbox("Status", ["All", "Open", "Acknowledged", "Investigating", "Resolved", "Closed"])
    with col2:
        priority_filter = st.selectbox("Priority", ["All", "P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Low"])
    with col3:
        assigned_filter = st.selectbox("Assigned To", ["All", "Me", "Unassigned", "analyst1", "analyst2"])
    with col4:
        st.write("")
        st.write("")
        if st.button("➕ Create Incident", type="primary"):
            st.session_state.show_create_incident = True
    
    # Create incident modal
    if st.session_state.get('show_create_incident'):
        with st.form("create_incident"):
            st.subheader("Create New Incident")
            title = st.text_input("Title")
            description = st.text_area("Description")
            col1, col2 = st.columns(2)
            with col1:
                priority = st.selectbox("Priority", ["P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Low"])
                incident_type = st.selectbox("Type", ["Prompt Injection", "Data Exfiltration", "Tool Misuse", "Goal Hijacking", "Policy Violation", "Other"])
            with col2:
                affected_agents = st.multiselect("Affected Agents", ["customer-service-bot", "data-analysis-agent", "code-review-bot"])
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Create", type="primary"):
                    st.success("✅ Incident created: INC-2026-00048")
                    st.session_state.show_create_incident = False
            with col2:
                if st.form_submit_button("Cancel"):
                    st.session_state.show_create_incident = False
    
    # Incidents list
    incidents = get_mock_incidents()
    
    for incident in incidents:
        priority_emoji = {"p1_critical": "🔴", "p2_high": "🟠", "p3_medium": "🟡", "p4_low": "🔵"}.get(incident['priority'], "⚪")
        
        with st.expander(f"{priority_emoji} {incident['number']} - {incident['title']}", expanded=False):
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.write("**Status:**")
                st.markdown(render_status_badge(incident['status']), unsafe_allow_html=True)
            with col2:
                st.write("**Priority:**")
                st.write(incident['priority'].replace("_", " ").upper())
            with col3:
                st.write("**Assigned To:**")
                st.write(incident['assigned_to'] or "Unassigned")
            with col4:
                st.write("**Created:**")
                st.write(incident['created_at'].strftime('%Y-%m-%d %H:%M'))
            
            st.write("**Affected Agents:**", ", ".join(incident['affected_agents']))
            
            # Actions
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                if st.button("✅ Acknowledge", key=f"ack_{incident['id']}"):
                    st.success("Acknowledged")
            with col2:
                if st.button("👤 Assign", key=f"assign_{incident['id']}"):
                    st.info("Assign dialog")
            with col3:
                if st.button("📝 Add Comment", key=f"comment_{incident['id']}"):
                    st.info("Comment dialog")
            with col4:
                if st.button("✔️ Resolve", key=f"resolve_{incident['id']}"):
                    st.success("Resolved")
            with col5:
                if st.button("📋 View Details", key=f"details_{incident['id']}"):
                    st.info("Full incident view")


# =============================================================================
# PAGE: AGENTS
# =============================================================================

def page_agents():
    """Agent onboarding + live monitoring (API-backed)."""
    st.title("🤖 Agent Monitoring & Onboarding")

    api_agents = api_list_agents(st.session_state.api_base_url, st.session_state.vf_api_key, limit=500)
    using_mock = not api_agents.get("ok")
    if using_mock:
        st.warning(f"Using demo fallback (API unavailable): {api_agents.get('error', 'unknown error')}")
        demo_agents = get_mock_agents()
        agents = [{
            "id": a.get("id"),
            "name": a.get("name"),
            "agent_type": a.get("agent_type"),
            "status": a.get("status"),
            "model_provider": None,
            "model_name": a.get("model"),
            "tools": [],
            "total_requests": a.get("total_requests", 0),
            "blocked_requests": a.get("blocked_requests", 0),
            "health_score": a.get("health_score", 0),
            "last_seen_at": a.get("last_seen").isoformat() if isinstance(a.get("last_seen"), datetime) else None,
        } for a in demo_agents]
    else:
        agents = api_agents.get("items", [])
        st.caption(f"Live API mode | agents in org: {api_agents.get('total', len(agents))}")

    col1, col2, col3, col4 = st.columns(4)
    healthy = len([a for a in agents if str(a.get('status', '')).lower() == 'healthy'])
    quarantined = len([a for a in agents if str(a.get('status', '')).lower() == 'quarantined'])
    unhealthy = len([a for a in agents if str(a.get('status', '')).lower() in ('degraded', 'unhealthy', 'offline')])
    with col1:
        st.metric("Total Agents", len(agents))
    with col2:
        st.metric("Healthy", healthy, delta=f"{healthy}/{max(1, len(agents))}")
    with col3:
        st.metric("Unhealthy", unhealthy)
    with col4:
        st.metric("Quarantined", quarantined)

    st.divider()
    tab1, tab2, tab3 = st.tabs(["Onboard Agents", "Import from Tessera", "Inventory"])

    with tab1:
        st.subheader("Register Single Agent")
        c1, c2 = st.columns(2)
        with c1:
            reg_name = st.text_input("Agent Name", key="vf_agent_reg_name", placeholder="customer-service-agent")
            reg_type = st.selectbox("Agent Type", ["langchain", "llamaindex", "custom", "autogen", "crewai"], key="vf_agent_reg_type")
            reg_provider = st.selectbox("Model Provider", ["", "openai", "anthropic", "ollama", "huggingface", "azure_openai", "custom"], key="vf_agent_reg_provider")
        with c2:
            reg_model = st.text_input("Model Name", key="vf_agent_reg_model", placeholder="gpt-4o / llama3.1 / mistral")
            reg_env = st.selectbox("Environment", ["production", "staging", "dev"], key="vf_agent_reg_env")
            reg_tools = st.text_input("Tools (comma separated)", key="vf_agent_reg_tools", placeholder="read_logs, search_docs")
        if st.button("➕ Register Agent", type="primary", use_container_width=True):
            payload = {
                "name": reg_name.strip(),
                "agent_type": reg_type,
                "model_provider": reg_provider or None,
                "model_name": reg_model.strip() or None,
                "tools": [t.strip() for t in reg_tools.split(",") if t.strip()],
                "environment": reg_env,
            }
            result = api_register_agent(st.session_state.api_base_url, st.session_state.vf_api_key, payload)
            if result.get("ok"):
                st.success(f"Registered: {result['item'].get('name')} ({result['item'].get('id')})")
            else:
                st.error(f"Registration failed: {result.get('error', 'unknown error')}")

        st.markdown("---")
        st.subheader("Bulk Onboarding")
        st.caption("Upload `.json` or `.csv` with: `name, agent_type, model_provider, model_name, tools, environment`.")
        upload = st.file_uploader("Agent Inventory File", type=["json", "csv"], key="vf_agent_bulk_upload")
        if upload is not None:
            try:
                rows = parse_agents_upload(upload)
                st.success(f"Validated {len(rows)} row(s).")
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                apply_bulk = st.checkbox("Register all rows via API", key="vf_apply_bulk_agents")
                if st.button("Apply Bulk Registration", disabled=not apply_bulk):
                    ok_count = 0
                    errors = []
                    for row in rows:
                        out = api_register_agent(st.session_state.api_base_url, st.session_state.vf_api_key, row)
                        if out.get("ok"):
                            ok_count += 1
                        else:
                            errors.append(f"{row.get('name')}: {out.get('error')}")
                    st.success(f"Registered/updated {ok_count}/{len(rows)} agents.")
                    if errors:
                        st.warning("Some rows failed:")
                        st.code("\n".join(errors[:20]), language="text")
            except Exception as exc:
                st.error(f"Bulk upload parsing failed: {exc}")

    with tab2:
        st.subheader("Import Agents from Tessera Registry")
        tessera = load_tessera_registry_agents()
        if not tessera.get("ok"):
            st.error(f"Tessera import unavailable: {tessera.get('error', 'unknown error')}")
            if tessera.get("path"):
                st.caption(f"Path checked: {tessera.get('path')}")
        else:
            items = tessera.get("items", [])
            st.caption(f"Source: {tessera.get('path')}")
            if not items:
                st.info("No agents found in Tessera registry.")
            else:
                view_df = pd.DataFrame([{
                    "name": i.get("name"),
                    "owner": i.get("_source_owner"),
                    "tenant": i.get("_source_tenant"),
                    "status": i.get("_source_status"),
                    "agent_type": i.get("agent_type"),
                    "model_provider": i.get("model_provider"),
                    "model_name": i.get("model_name"),
                    "tools": ", ".join(i.get("tools", [])),
                } for i in items])
                st.dataframe(view_df, use_container_width=True, hide_index=True)

                active_only = st.checkbox("Only sync active Tessera agents", value=True, key="vf_tessera_active_only")
                candidate_items = [i for i in items if (not active_only) or str(i.get("_source_status", "")).lower() == "active"]
                names = [i.get("name") for i in candidate_items]
                selected_names = st.multiselect("Select agents to sync", options=names, default=names)

                if st.button("Sync Selected to VerityFlux", type="primary", disabled=not selected_names):
                    selected_set = set(selected_names)
                    to_sync = [i for i in candidate_items if i.get("name") in selected_set]
                    ok_count = 0
                    errors = []
                    for row in to_sync:
                        payload = {
                            "name": row.get("name"),
                            "agent_type": row.get("agent_type"),
                            "model_provider": row.get("model_provider"),
                            "model_name": row.get("model_name"),
                            "tools": row.get("tools", []),
                            "environment": row.get("environment", "production"),
                        }
                        out = api_register_agent(st.session_state.api_base_url, st.session_state.vf_api_key, payload)
                        if out.get("ok"):
                            ok_count += 1
                        else:
                            errors.append(f"{row.get('name')}: {out.get('error')}")
                    st.success(f"Synced {ok_count}/{len(to_sync)} agents from Tessera.")
                    if errors:
                        st.warning("Some agents failed:")
                        st.code("\n".join(errors[:20]), language="text")

    with tab3:
        st.subheader("Monitored Agent Inventory")
        if not agents:
            st.info("No agents found yet. Use Onboard Agents tab to register.")
            return
        df = pd.DataFrame([{
            "id": a.get("id"),
            "name": a.get("name"),
            "status": str(a.get("status", "")).upper(),
            "agent_type": a.get("agent_type"),
            "model_provider": a.get("model_provider"),
            "model_name": a.get("model_name"),
            "health_score": a.get("health_score"),
            "requests": a.get("total_requests"),
            "blocked": a.get("blocked_requests"),
            "last_seen": format_timestamp(a.get("last_seen_at")),
        } for a in agents])
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("Runtime Actions")
        selectable = {f"{a.get('name')} ({a.get('id')})": a.get("id") for a in agents}
        selected = st.selectbox("Select Agent", list(selectable.keys()))
        selected_id = selectable[selected]
        action_col1, action_col2 = st.columns(2)
        with action_col1:
            if st.button("📡 Send Heartbeat"):
                try:
                    req = urllib.request.Request(
                        f"{st.session_state.api_base_url.rstrip('/')}/api/v1/soc/agents/{selected_id}/heartbeat",
                        data=json.dumps({"blocked": False}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    if st.session_state.vf_api_key:
                        req.add_header("X-API-Key", st.session_state.vf_api_key)
                        req.add_header("Authorization", f"Bearer {st.session_state.vf_api_key}")
                    with urllib.request.urlopen(req, timeout=6):
                        pass
                    st.success("Heartbeat submitted.")
                except Exception as exc:
                    st.error(f"Heartbeat failed: {exc}")
        with action_col2:
            reason = st.text_input("Quarantine Reason", value="Runtime policy violation", key="vf_quarantine_reason")
            if st.button("🔒 Quarantine Agent"):
                result = api_quarantine_agent(st.session_state.api_base_url, st.session_state.vf_api_key, selected_id, reason)
                if result.get("ok"):
                    st.warning(f"Agent quarantined: {selected_id}")
                else:
                    st.error(f"Quarantine failed: {result.get('error', 'unknown error')}")


# =============================================================================
# PAGE: HITL APPROVALS
# =============================================================================

def page_approvals():
    """HITL Approval Queue"""
    st.title("✋ Approval Queue")
    
    approvals = get_mock_approvals()
    
    # Summary
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Pending", len(approvals))
    with col2:
        critical = len([a for a in approvals if a['risk_level'] == 'critical'])
        st.metric("Critical", critical)
    with col3:
        st.metric("Avg Wait Time", "8.5 min")
    with col4:
        st.metric("Today's Decisions", 47)
    
    st.divider()
    
    # Bulk actions
    col1, col2, col3 = st.columns([1, 1, 3])
    with col1:
        if st.button("✅ Bulk Approve Selected"):
            st.success("Selected items approved")
    with col2:
        if st.button("❌ Bulk Deny Selected"):
            st.warning("Selected items denied")
    
    # Approval cards
    for approval in approvals:
        time_remaining = (approval["expires_at"] - datetime.now()).total_seconds() / 60
        urgency_color = "#dc3545" if time_remaining < 10 else "#ffc107" if time_remaining < 20 else "#28a745"
        
        with st.container():
            st.markdown(f"""
                <div style="background: #1e1e1e; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid {urgency_color};">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-size: 1.1rem; font-weight: bold;">{approval['title']}</span>
                        {render_severity_badge(approval['risk_level'])}
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.write(f"**Agent:** {approval['agent']}")
                st.write(f"**Tool:** {approval['tool']}")
            with col2:
                st.write(f"**Risk Score:** {approval['risk_score']}%")
                st.write(f"**Time Remaining:** {int(time_remaining)} min")
            with col3:
                st.write("**Reasoning:**")
                st.write("User requested data export...")
            with col4:
                # Progress bar for time remaining
                progress = min(1.0, time_remaining / 30)
                st.progress(progress, text=f"⏱️ {int(time_remaining)}m")
            
            # Decision buttons
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                if st.button("✅ Approve", key=f"approve_{approval['id']}", type="primary"):
                    st.success("Approved!")
            with col2:
                if st.button("✅ Approve Session", key=f"approve_session_{approval['id']}"):
                    st.success("Approved for session")
            with col3:
                if st.button("❌ Deny", key=f"deny_{approval['id']}"):
                    st.warning("Denied")
            with col4:
                if st.button("⬆️ Escalate", key=f"escalate_{approval['id']}"):
                    st.info("Escalated")
            with col5:
                if st.button("🔍 Details", key=f"details_{approval['id']}"):
                    st.info("Full details")
            
            st.divider()


# =============================================================================
# PAGE: VULNERABILITIES
# =============================================================================

def page_vulnerabilities():
    """Vulnerability Database Browser"""
    st.title("📚 Vulnerability Database")
    
    tab1, tab2, tab3 = st.tabs(["OWASP LLM Top 10", "OWASP Agentic Top 10", "All Vulnerabilities"])
    
    vulns = get_vulnerability_catalog()
    
    with tab1:
        st.subheader("OWASP LLM Top 10 (2025)")
        
        llm_vulns = [v for v in vulns if v['source'] == 'OWASP LLM Top 10 (2025)']
        
        for vuln in llm_vulns:
            with st.expander(f"{vuln['vuln_id']}: {vuln['title']}", expanded=False):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write("**Severity:**")
                    st.markdown(render_severity_badge(vuln['severity']), unsafe_allow_html=True)
                with col2:
                    st.metric("CVSS Score", vuln.get('cvss', 'N/A'))
                with col3:
                    st.write("**Source:**", vuln['source'])
                
                st.write("**Description:**")
                st.write(vuln.get("description", "No description."))
                
                st.write("**Recommendation:**")
                for rec in vuln.get("recommendations", []):
                    st.write(f"- {rec}")
    
    with tab2:
        st.subheader("OWASP Agentic Top 10 (2025)")
        
        agentic_vulns = [v for v in vulns if v['source'] == 'OWASP Agentic Top 10 (2025)']
        
        for vuln in agentic_vulns:
            with st.expander(f"{vuln['vuln_id']}: {vuln['title']}", expanded=False):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write("**Severity:**")
                    st.markdown(render_severity_badge(vuln['severity']), unsafe_allow_html=True)
                with col2:
                    st.metric("CVSS Score", vuln.get('cvss', 'N/A'))
                with col3:
                    st.write("**Source:**", vuln['source'])
                st.write("**Description:**")
                st.write(vuln.get("description", "No description."))
                st.write("**Recommendation:**")
                for rec in vuln.get("recommendations", []):
                    st.write(f"- {rec}")
    
    with tab3:
        st.subheader("Search Vulnerabilities")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            search = st.text_input("Search", placeholder="Search by ID, title, or keyword...")
        with col2:
            source_filter = st.multiselect(
                "Source",
                sorted(list(set(v["source"] for v in vulns))),
            )
        with col3:
            severity_filter = st.multiselect("Severity", ["critical", "high", "medium", "low"])
        
        filtered = []
        query = (search or "").strip().lower()
        for vuln in vulns:
            if source_filter and vuln.get("source") not in source_filter:
                continue
            if severity_filter and vuln.get("severity") not in severity_filter:
                continue
            if query:
                haystack = " ".join([
                    vuln.get("vuln_id", ""),
                    vuln.get("title", ""),
                    vuln.get("description", ""),
                    vuln.get("technical_impact", ""),
                    vuln.get("business_impact", ""),
                ]).lower()
                if query not in haystack:
                    continue
            filtered.append(vuln)

        # Results table
        df = pd.DataFrame([{
            "vuln_id": v.get("vuln_id"),
            "title": v.get("title"),
            "severity": v.get("severity"),
            "source": v.get("source"),
            "technical_impact": v.get("technical_impact"),
            "business_impact": v.get("business_impact"),
        } for v in filtered])
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Sync button
        if st.button("🔄 Sync from External Sources"):
            with st.spinner("Syncing from NVD, MITRE ATLAS, GitHub..."):
                time.sleep(2)
                st.success("✅ Synced 15 new vulnerabilities")


# =============================================================================
# PAGE: INTEGRATIONS
# =============================================================================

def page_integrations():
    """Integration Configuration"""
    st.title("🔌 Integrations")
    
    tab1, tab2, tab3 = st.tabs(["Configured", "Add New", "Notification Rules"])
    
    with tab1:
        st.subheader("Configured Integrations")
        
        integrations = [
            {"name": "Slack - Security Alerts", "type": "slack", "status": "connected", "last_used": "2 min ago"},
            {"name": "Jira - Security Project", "type": "jira", "status": "connected", "last_used": "15 min ago"},
            {"name": "PagerDuty", "type": "pagerduty", "status": "connected", "last_used": "1 hour ago"},
            {"name": "Email - SOC Team", "type": "email", "status": "connected", "last_used": "30 min ago"},
        ]
        
        for integration in integrations:
            icon = {"slack": "💬", "jira": "📋", "pagerduty": "📟", "email": "📧", "webhook": "🔗"}.get(integration['type'], "🔌")
            
            with st.expander(f"{icon} {integration['name']}", expanded=False):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Type:** {integration['type'].capitalize()}")
                    st.write(f"**Status:** {integration['status'].capitalize()}")
                with col2:
                    st.write(f"**Last Used:** {integration['last_used']}")
                with col3:
                    if st.button("🧪 Test", key=f"test_{integration['name']}"):
                        st.success("Connection successful!")
                    if st.button("🗑️ Delete", key=f"delete_{integration['name']}"):
                        st.warning("Deleted")
    
    with tab2:
        st.subheader("Add New Integration")
        
        integration_type = st.selectbox(
            "Integration Type",
            ["Slack", "Jira", "PagerDuty", "Email (SMTP)", "Twilio (SMS)", "Webhook", "SIEM"]
        )
        
        if integration_type == "Slack":
            st.text_input("Bot Token", type="password", placeholder="xoxb-...")
            st.text_input("Default Channel", value="#security-alerts")
            st.text_input("Critical Channel", value="#security-critical")
        
        elif integration_type == "Jira":
            st.text_input("Jira URL", placeholder="https://company.atlassian.net")
            st.text_input("Username/Email")
            st.text_input("API Token", type="password")
            st.text_input("Project Key", value="SEC")
        
        elif integration_type == "PagerDuty":
            st.text_input("Routing Key", type="password")
        
        elif integration_type == "Email (SMTP)":
            col1, col2 = st.columns(2)
            with col1:
                st.text_input("SMTP Host", placeholder="smtp.gmail.com")
                st.number_input("SMTP Port", value=587)
            with col2:
                st.text_input("Username")
                st.text_input("Password", type="password")
            st.text_input("From Address")
            st.text_area("To Addresses (one per line)")
        
        if st.button("💾 Save Integration", type="primary"):
            st.success("✅ Integration saved!")
    
    with tab3:
        st.subheader("Notification Rules")
        
        st.write("Configure which integrations receive which notifications:")
        
        rules = [
            {"integration": "Slack", "types": ["incidents", "alerts", "approvals"], "priority": "medium+"},
            {"integration": "PagerDuty", "types": ["incidents"], "priority": "high+"},
            {"integration": "Email", "types": ["incidents", "alerts", "scan_complete"], "priority": "all"},
        ]
        
        for rule in rules:
            with st.expander(f"📋 {rule['integration']}", expanded=False):
                st.multiselect(
                    "Notification Types",
                    ["incidents", "alerts", "approvals", "scan_complete", "agent_status"],
                    default=rule['types'],
                    key=f"types_{rule['integration']}"
                )
                st.selectbox(
                    "Minimum Priority",
                    ["all", "low+", "medium+", "high+", "critical only"],
                    index=["all", "low+", "medium+", "high+", "critical only"].index(rule['priority']),
                    key=f"priority_{rule['integration']}"
                )


# =============================================================================
# PAGE: FIREWALL ACTIVITY
# =============================================================================

def page_firewall_activity():
    """Runtime cognitive firewall activity."""
    st.title("🧠 Cognitive Firewall Activity")
    st.caption("Runtime decisions from flight recorder and structured firewall logs.")

    events = get_firewall_activity(limit=500)
    if not events:
        st.info("No firewall runtime activity found yet.")
        st.caption("Trigger gatekeeping or scan actions to generate firewall decisions.")
        return

    window_hours = st.slider("Recency Window (hours)", min_value=1, max_value=168, value=24, step=1)
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    def _to_dt(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None

    recent = []
    for e in events:
        ts = _to_dt(e.get("timestamp"))
        if ts and ts >= cutoff:
            recent.append(e)

    if recent:
        events = recent
    else:
        st.warning("No firewall events in selected recency window; showing latest available history.")

    total = len(events)
    blocked = len([e for e in events if str(e.get("decision")).lower() == "block"])
    approvals = len([e for e in events if str(e.get("decision")).lower() in ("require_approval", "log_only")])
    allowed = len([e for e in events if str(e.get("decision")).lower() == "allow"])
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Decisions", total)
    c2.metric("Blocked", blocked)
    c3.metric("Require Approval/Log", approvals)
    c4.metric("Allowed", allowed)

    st.divider()
    if events:
        st.caption(
            f"Showing {len(events)} events | "
            f"newest: {format_timestamp(events[0].get('timestamp'))} | "
            f"oldest: {format_timestamp(events[-1].get('timestamp'))}"
        )
    st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)


# =============================================================================
# PAGE: SETTINGS
# =============================================================================

def page_settings():
    """Settings"""
    st.title("⚙️ Settings")
    
    tab1, tab2, tab3, tab4 = st.tabs(["General", "Security", "API Keys", "Subscription"])
    
    with tab1:
        st.subheader("General Settings")
        
        st.text_input("Organization Name", value="Acme Corp")
        st.selectbox("Timezone", ["UTC", "America/New_York", "America/Los_Angeles", "Europe/London"])
        st.selectbox("Date Format", ["YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY"])

        st.divider()
        st.subheader("API Settings")
        api_url = st.text_input("API Base URL", value=st.session_state.api_base_url)
        if api_url and api_url != st.session_state.api_base_url:
            st.session_state.api_base_url = api_url

        st.divider()
        st.subheader("Audit (Vestigia) Settings")
        vest_url = st.text_input("Vestigia API URL", value=st.session_state.vestigia_api_url)
        if vest_url and vest_url != st.session_state.vestigia_api_url:
            st.session_state.vestigia_api_url = vest_url
        vest_key = st.text_input("Vestigia API Key (optional)", type="password", value=st.session_state.vestigia_api_key)
        if vest_key != st.session_state.vestigia_api_key:
            st.session_state.vestigia_api_key = vest_key
        
        st.divider()
        
        st.subheader("Notification Preferences")
        st.checkbox("Email notifications", value=True)
        st.checkbox("Slack notifications", value=True)
        st.checkbox("Browser notifications", value=False)
    
    with tab2:
        st.subheader("Security Settings")
        
        st.subheader("HITL Configuration")
        st.slider("Auto-approve below risk score", 0, 100, 30)
        st.slider("Auto-deny above risk score", 0, 100, 95)
        st.number_input("Default approval timeout (minutes)", value=30)
        st.checkbox("Require justification for approvals", value=True)
        
        st.divider()
        
        st.subheader("Agent Defaults")
        st.slider("Default risk threshold", 0, 100, 70)
        st.checkbox("Enable firewall by default", value=True)
        st.checkbox("Require HITL for new agents", value=True)

        st.divider()

        st.subheader("Enforcement Policy")
        st.caption("Policy is stored on the API service. Restart the API after updates.")

        api_key = st.text_input(
            "API Key (for policy update)",
            type="password",
            help="Uses X-API-Key header",
            value=st.session_state.vf_api_key,
            key="vf_api_key_input",
        )
        st.session_state.vf_api_key = api_key
        role = st.selectbox("Your Role", ["admin", "analyst", "viewer"], index=0)
        is_admin = role == "admin"
        api_base = st.session_state.api_base_url

        if st.button("🔄 Load Policy", key="load_policy"):
            result = api_get_policy(api_base, api_key)
            if result.get("ok"):
                st.session_state.policy_cache = result.get("policy", {})
                st.session_state.policy_cache_path = result.get("path")
                st.success(f"Policy loaded from {st.session_state.policy_cache_path}")
            else:
                st.error(f"Failed to load policy from API: {result.get('error', 'unknown error')}")

        policy_text = st.text_area(
            "Policy JSON",
            value=json.dumps(st.session_state.policy_cache or {}, indent=2),
            height=220
        )

        if st.button("💾 Save Policy", key="save_policy", disabled=not is_admin):
            try:
                policy_json = json.loads(policy_text) if policy_text.strip() else {}
            except Exception as e:
                st.error(f"Invalid JSON: {e}")
                policy_json = None
            if policy_json is not None:
                result = api_update_policy(api_base, api_key, policy_json)
                if result.get("ok"):
                    st.session_state.policy_cache = result.get("policy", {})
                    st.session_state.policy_cache_path = result.get("path")
                    st.success(f"Policy saved to {st.session_state.policy_cache_path}")
                    st.info(result.get("note", "Restart required to apply changes."))
                else:
                    st.error(f"Failed to save policy to API: {result.get('error', 'unknown error')}")

        if st.button("🔁 Reload Policy (Live)", key="reload_policy", disabled=not is_admin):
            try:
                req = urllib.request.Request(f"{api_base}/api/v1/policy/reload", method="POST")
                if api_key:
                    req.add_header("X-API-Key", api_key)
                    req.add_header("Authorization", f"Bearer {api_key}")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                st.success("Policy reloaded in live firewall instances.")
                st.session_state.policy_cache = data.get("policy", {})
            except Exception as e:
                st.error(f"Reload failed: {e}")

        if not is_admin:
            st.info("Policy updates are restricted to admin role.")

        st.divider()
        st.subheader("Policy Change History (from Vestigia)")
        if st.button("📥 Load Policy Audit Events", key="load_policy_events"):
            audit = api_get_vestigia_policy_events(
                st.session_state.vestigia_api_url,
                st.session_state.vestigia_api_key,
                limit=100,
            )
            if audit and isinstance(audit, dict) and audit.get("ok"):
                st.session_state.policy_audit = audit.get("events", [])
                if audit.get("_source") == "shared_log_fallback":
                    st.warning("Vestigia API unavailable; showing policy events from shared audit log fallback.")
            else:
                st.session_state.policy_audit = []
                st.error(f"Failed to load audit events from Vestigia: {(audit or {}).get('error', 'unknown error')}")

        events = st.session_state.get("policy_audit", [])
        policy_events = [
            e for e in events
            if str(e.get("action_type", "")).lower() in ("policy_updated", "policy_reloaded")
        ]
        if policy_events:
            df = pd.DataFrame([
                {
                    "timestamp": e.get("timestamp"),
                    "action": e.get("action_type"),
                    "actor": e.get("actor_id"),
                    "status": e.get("status"),
                }
                for e in policy_events
            ])
            st.dataframe(df, use_container_width=True)
        else:
            st.caption("No policy events found yet.")
    
    with tab3:
        st.subheader("API Keys")
        
        # Existing keys
        st.write("**Your API Keys:**")
        keys = [
            {"name": "Production API", "prefix": "vf_prod_", "created": "2026-01-15", "last_used": "2 hours ago"},
            {"name": "Development", "prefix": "vf_dev_", "created": "2026-01-20", "last_used": "1 day ago"},
        ]
        
        for key in keys:
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            with col1:
                st.write(f"**{key['name']}**")
                st.caption(f"Prefix: {key['prefix']}***")
            with col2:
                st.write(f"Created: {key['created']}")
            with col3:
                st.write(f"Last used: {key['last_used']}")
            with col4:
                if st.button("🗑️", key=f"delete_key_{key['prefix']}"):
                    st.warning("Key revoked")
        
        st.divider()
        
        # Create new key
        st.write("**Create New API Key:**")
        key_name = st.text_input("Key Name", placeholder="My API Key")
        key_permissions = st.multiselect("Permissions", ["read", "write", "admin"], default=["read"])
        key_expiry = st.number_input("Expires in (days)", value=365)
        
        if st.button("🔑 Generate API Key"):
            st.success("API Key generated!")
            st.code("vf_abc123xyz789...", language=None)
            st.warning("⚠️ Copy this key now. You won't be able to see it again!")
    
    with tab4:
        st.subheader("Subscription")
        
        st.info("**Current Plan:** Professional")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Scans Used", "142 / Unlimited")
            st.metric("Agents", "24 / 25")
        with col2:
            st.metric("Evaluations", "45,230 / 100,000")
            st.metric("Users", "12 / 50")
        
        st.divider()
        
        st.write("**Available Plans:**")
        
        plans = [
            {"name": "Startup", "price": "$99/mo", "features": ["50 scans/mo", "5 agents", "10K evaluations"]},
            {"name": "Professional", "price": "$499/mo", "features": ["Unlimited scans", "25 agents", "100K evaluations"], "current": True},
            {"name": "Enterprise", "price": "Custom", "features": ["Everything unlimited", "On-premise", "SSO", "Dedicated support"]},
        ]
        
        cols = st.columns(3)
        for i, plan in enumerate(plans):
            with cols[i]:
                st.markdown(f"""
                    <div style="background: {'#1e3a5f' if plan.get('current') else '#1e1e1e'}; padding: 1.5rem; border-radius: 10px; text-align: center; {'border: 2px solid #007bff;' if plan.get('current') else ''}">
                        <h3>{plan['name']}</h3>
                        <p style="font-size: 1.5rem; font-weight: bold;">{plan['price']}</p>
                        <ul style="text-align: left; padding-left: 1.5rem;">
                            {''.join([f"<li>{f}</li>" for f in plan['features']])}
                        </ul>
                    </div>
                """, unsafe_allow_html=True)
                
                if plan.get('current'):
                    st.button("Current Plan", disabled=True, key=f"plan_{plan['name']}")
                else:
                    st.button(f"Upgrade to {plan['name']}", key=f"plan_{plan['name']}")


# =============================================================================
# SIDEBAR NAVIGATION
# =============================================================================

def render_sidebar():
    """Render sidebar navigation"""
    with st.sidebar:
        st.image("https://via.placeholder.com/200x50?text=VerityFlux", use_container_width=True)
        st.markdown("---")
        
        # User info
        st.markdown("""
            <div style="text-align: center; padding: 1rem 0;">
                <div style="font-size: 2rem;">👤</div>
                <div style="font-weight: bold;">Admin User</div>
                <div style="color: #888; font-size: 0.8rem;">admin@acmecorp.com</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Navigation
        pages = {
            "dashboard": ("🛡️", "SOC Dashboard"),
            "scanner": ("🔍", "Security Scanner"),
            "firewall": ("🧠", "Firewall Activity"),
            "incidents": ("🚨", "Incidents"),
            "agents": ("🤖", "Agents"),
            "approvals": ("✋", "Approvals"),
            "vulnerabilities": ("📚", "Vulnerabilities"),
            "integrations": ("🔌", "Integrations"),
            "settings": ("⚙️", "Settings"),
        }
        
        for page_id, (icon, label) in pages.items():
            if st.button(f"{icon} {label}", key=f"nav_{page_id}", use_container_width=True):
                st.session_state.current_page = page_id
                st.rerun()
        
        st.markdown("---")
        
        # Quick stats
        metrics = get_mock_metrics()
        st.markdown(f"""
            <div style="padding: 0.5rem; background: #1e1e1e; border-radius: 5px;">
                <div style="font-size: 0.8rem; color: #888;">Quick Stats</div>
                <div>🚨 {metrics['incidents']['open']} open incidents</div>
                <div>⏳ {len(get_mock_approvals())} pending approvals</div>
                <div>🤖 {metrics['agents']['healthy']}/{metrics['agents']['total']} agents healthy</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Version
        st.caption("VerityFlux Enterprise v3.5.0")


# =============================================================================
# MAIN APP
# =============================================================================

def main():
    """Main application"""
    render_sidebar()
    
    # Route to current page
    page_routes = {
        "dashboard": page_dashboard,
        "scanner": page_scanner,
        "firewall": page_firewall_activity,
        "incidents": page_incidents,
        "agents": page_agents,
        "approvals": page_approvals,
        "vulnerabilities": page_vulnerabilities,
        "integrations": page_integrations,
        "settings": page_settings,
    }
    
    current_page = st.session_state.get('current_page', 'dashboard')
    page_func = page_routes.get(current_page, page_dashboard)
    page_func()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Tessera IAM Dashboard - Fully Integrated with Vestigia
Logs all events to shared audit trail for suite-wide visibility

Run: streamlit run web_ui/tessera_dashboard.py
Save as: ~/ml-redteam/tessera/web_ui/tessera_dashboard.py
"""

import streamlit as st
import sys
import os
import json
import csv
import io
import time
from pathlib import Path
from datetime import datetime, timedelta
from urllib import request as urllib_request

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import Tessera modules
try:
    from tessera.registry import TesseraRegistry, AgentIdentity
    from tessera.token_generator import TokenGenerator
    from tessera.gatekeeper import Gatekeeper, AccessDecision
    from tessera.revocation import RevocationList
    
    # Try Redis but don't fail if unavailable
    try:
        from tessera.redis_stream import TesseraRedisStream
        REDIS_AVAILABLE = True
    except:
        REDIS_AVAILABLE = False
        
except ImportError as e:
    st.error(f"❌ Import Error: {e}")
    st.info("Please ensure Tessera modules are in your Python path")
    st.stop()

# ============================================
# VESTIGIA INTEGRATION
# ============================================

def resolve_suite_audit_log_path() -> str:
    """Resolve the shared audit log path used by Tessera UI."""
    default_log = str(Path(__file__).parent.parent.parent / "shared_state" / "shared_audit.log")
    audit_log = os.getenv('SUITE_AUDIT_LOG', default_log)
    if not os.path.isabs(audit_log):
        audit_log = str(Path(__file__).parent.parent.parent / audit_log)
    return audit_log


class VestigiaBridge:
    """Logs Tessera events to Vestigia's shared audit log"""
    
    def __init__(self):
        # Get shared audit log from environment (normalize to absolute path)
        self.audit_log = resolve_suite_audit_log_path()
        
        # Ensure directory exists
        Path(self.audit_log).parent.mkdir(parents=True, exist_ok=True)
        
        # Create log if it doesn't exist
        if not Path(self.audit_log).exists():
            with open(self.audit_log, 'w') as f:
                f.write(f"# Sovereign Security Suite - Shared Audit Log\n")
                f.write(f"# Started: {datetime.utcnow().isoformat()}\n")
    
    def log_event(self, event_type: str, agent_id: str, tool: str, status: str, details: str = ""):
        """Write event to shared audit log"""
        try:
            timestamp = datetime.utcnow().isoformat()
            
            # Format: timestamp | source | event_type | agent | tool | status | details
            log_entry = f"{timestamp} | TESSERA | {event_type} | Agent: {agent_id} | Tool: {tool} | Status: {status}"
            
            if details:
                log_entry += f" | {details}"
            
            log_entry += "\n"
            
            # Atomic write
            with open(self.audit_log, 'a') as f:
                f.write(log_entry)
            
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to log to Vestigia: {e}")
            return False

# Initialize bridge globally
vestigia = VestigiaBridge()


def suite_integration_active() -> bool:
    """Detect integration through either shared-log wiring or API event forwarding."""
    audit_log = resolve_suite_audit_log_path()
    shared_log_active = 'shared_state' in audit_log or Path(audit_log).exists()

    integration_enabled = os.getenv("MLRT_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes")
    ingest_url = os.getenv("MLRT_VESTIGIA_INGEST_URL", "")
    api_integration_active = integration_enabled and "/events" in ingest_url

    return shared_log_active or api_integration_active

# ============================================
# PAGE CONFIG
# ============================================

st.set_page_config(
    page_title="Tessera IAM Control Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# STYLING
# ============================================

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #161b33 0%, #1e2642 100%);
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-active {
        background-color: #26a641;
        box-shadow: 0 0 10px rgba(38, 166, 65, 0.5);
        animation: pulse 2s infinite;
    }
    
    .status-inactive {
        background-color: #6e7681;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .event-row {
        padding: 12px;
        margin: 8px 0;
        border-radius: 8px;
        border-left: 4px solid #238636;
        background-color: #0d1117;
    }
    
    .event-denied {
        border-left-color: #da3633;
    }
    
    .token-display {
        background: #161b22;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #30363d;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        word-break: break-all;
    }
    
    .integration-badge {
        background: #1e3a1e;
        padding: 8px 16px;
        border-radius: 6px;
        border-left: 4px solid #4ade80;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# SESSION STATE INITIALIZATION
# ============================================

def initialize_state():
    """Initialize session state"""
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True
        st.session_state.registry = TesseraRegistry()
        # Demo-friendly defaults for UI usage
        os.environ.setdefault("TESSERA_REQUIRE_DPOP", "false")
        os.environ.setdefault("TESSERA_REQUIRE_MEMORY_BINDING", "false")

        st.session_state.token_gen = TokenGenerator(st.session_state.registry)
        st.session_state.revocation_list = RevocationList()
        st.session_state.gatekeeper = Gatekeeper(
            st.session_state.token_gen,
            st.session_state.revocation_list
        )
        
        if REDIS_AVAILABLE:
            try:
                st.session_state.redis_stream = TesseraRedisStream()
            except:
                st.session_state.redis_stream = None
        else:
            st.session_state.redis_stream = None
        
        st.session_state.local_events = []
        st.session_state.token_history = []
        st.session_state.last_generated_token = None
        st.session_state.last_generated_tool = ""
        st.session_state.gatekeeper_token_input = ""
        st.session_state.gatekeeper_tool_input = ""
        st.session_state.auto_refresh = False

initialize_state()

# ============================================
# HELPER FUNCTIONS
# ============================================

def _parse_timestamp(ts):
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


def format_timestamp(ts) -> str:
    dt = _parse_timestamp(ts)
    if not dt:
        return str(ts) if ts else "N/A"
    base = dt.strftime("%Y-%m-%d %H:%M:%S")
    zone = dt.tzname() or ("UTC" if dt.tzinfo else "local")
    return f"{base} {zone} ({_relative_time(dt)})"

def add_local_event(event_type, agent_id, tool, status, details=""):
    """Add event to local storage AND log to Vestigia"""
    event = {
        'type': event_type,
        'agent': agent_id,
        'tool': tool,
        'status': status,
        'timestamp': datetime.now().isoformat(),
        'details': details or "",
    }
    st.session_state.local_events.insert(0, event)
    
    # Keep only last 100 events
    if len(st.session_state.local_events) > 100:
        st.session_state.local_events = st.session_state.local_events[:100]
    
    # 🎯 LOG TO VESTIGIA
    vestigia.log_event(event_type, agent_id, tool, status, details)
    _forward_event_to_vestigia_api(event_type, agent_id, tool, status, details)

    redis = st.session_state.redis_stream
    if redis and redis.is_available():
        try:
            redis.broadcast_event(event_type, agent_id, tool, status, details)
            normalized_type = str(event_type).lower()
            normalized_status = str(status).lower()
            if normalized_type == "token_issued":
                redis.increment_metric("tokens_issued")
            if normalized_status == "denied":
                redis.increment_metric("tokens_denied")
            if normalized_status in ("granted", "success"):
                redis.increment_metric("validations_allowed")
        except Exception:
            pass


def _forward_event_to_vestigia_api(event_type: str, agent_id: str, tool: str, status: str, details: str = "") -> None:
    """Best-effort forward of UI events into Vestigia API ledger."""
    integration_enabled = os.getenv("MLRT_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes")
    if not integration_enabled:
        return

    ingest_url = os.getenv("MLRT_VESTIGIA_INGEST_URL")
    if not ingest_url:
        api_base = os.getenv("VESTIGIA_API_BASE", "http://localhost:8002")
        ingest_url = f"{api_base.rstrip('/')}/events"

    api_key = os.getenv("MLRT_VESTIGIA_API_KEY") or os.getenv("VESTIGIA_API_KEY", "")
    payload = {
        "actor_id": agent_id,
        "action_type": event_type,
        "status": status,
        "evidence": {
            "summary": details or f"{event_type} from Tessera UI",
            "tool": tool,
            "source": "tessera_ui",
            "timestamp": datetime.utcnow().isoformat(),
        },
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
        with urllib_request.urlopen(req, timeout=2):
            pass
    except Exception:
        # Never break UI actions if API forwarding fails.
        return

def get_events(limit=50):
    """Get events from Redis or local storage"""
    redis = st.session_state.redis_stream
    
    if redis and redis.is_available():
        return redis.get_event_history(limit=limit)
    else:
        return st.session_state.local_events[:limit]

def get_metrics():
    """Get metrics from Redis or calculate from local storage"""
    redis = st.session_state.redis_stream
    
    if redis and redis.is_available():
        return redis.get_all_metrics()
    else:
        events = st.session_state.local_events
        return {
            'tokens_issued': len([e for e in events if e['type'] == 'TOKEN_ISSUED']),
            'tokens_denied': len([e for e in events if str(e['status']).lower() == 'denied']),
            'validations_allowed': len([e for e in events if str(e['status']).lower() in ('granted', 'success')])
        }


def persist_registry() -> None:
    """Persist registry changes safely to disk."""
    registry = st.session_state.registry
    out = {}
    for agent_id, agent in registry.agents.items():
        out[agent_id] = {
            "agent_id": agent.agent_id,
            "owner": agent.owner,
            "tenant_id": getattr(agent, "tenant_id", "default"),
            "status": agent.status,
            "allowed_tools": list(agent.allowed_tools or []),
            "max_token_ttl": int(agent.max_token_ttl),
            "risk_threshold": int(agent.risk_threshold),
            "trust_score": float(getattr(agent, "trust_score", 100.0)),
            "trust_dependencies": list(getattr(agent, "trust_dependencies", []) or []),
            "status_reason": getattr(agent, "status_reason", None),
            "last_updated": getattr(agent, "last_updated", None),
            "metadata": getattr(agent, "metadata", None),
        }
    with open(registry.registry_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def parse_agents_upload(uploaded_file) -> list:
    """Parse JSON/CSV upload into normalized agent rows."""
    name = uploaded_file.name.lower()
    data = uploaded_file.read()
    rows = []

    if name.endswith(".json"):
        payload = json.loads(data.decode("utf-8"))
        if isinstance(payload, dict):
            payload = payload.get("agents", [])
        if not isinstance(payload, list):
            raise ValueError("JSON must be a list of agent objects or {'agents': [...]}.")
        rows = payload
    elif name.endswith(".csv"):
        text = data.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
    else:
        raise ValueError("Unsupported file type. Use .json or .csv.")

    normalized = []
    for i, row in enumerate(rows, start=1):
        agent_id = str(row.get("agent_id", "")).strip()
        owner = str(row.get("owner", "")).strip()
        if not agent_id or not owner:
            raise ValueError(f"Row {i}: 'agent_id' and 'owner' are required.")

        tools = row.get("allowed_tools", [])
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(",") if t.strip()]
        elif not isinstance(tools, list):
            tools = []

        normalized.append({
            "agent_id": agent_id,
            "owner": owner,
            "tenant_id": str(row.get("tenant_id", "default") or "default"),
            "status": str(row.get("status", "active") or "active"),
            "allowed_tools": tools,
            "max_token_ttl": int(row.get("max_token_ttl", 3600) or 3600),
            "risk_threshold": int(row.get("risk_threshold", 50) or 50),
        })
    return normalized

# ============================================
# SIDEBAR
# ============================================

with st.sidebar:
    st.markdown("### 🛡️ Tessera Control Center")
    
    # Connection status
    redis = st.session_state.redis_stream
    if redis and redis.is_available():
        st.markdown('<span class="status-indicator status-active"></span> **LIVE** (Redis Connected)', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-indicator status-inactive"></span> **Local Mode**', unsafe_allow_html=True)
    
    st.markdown("---")
    
    mode = st.radio("Navigation", [
        "📊 Dashboard",
        "🤖 Agent Registry",
        "🔑 Token Generator",
        "🛡️ Gatekeeper",
        "🚫 Revocation Manager",
        "📜 Event History",
        "📤 Bulk Uploads",
    ])
    
    st.markdown("---")
    
    # Quick metrics
    metrics = get_metrics()
    st.metric("Tokens Issued", metrics.get('tokens_issued', 0))
    st.metric("Active Agents", len(st.session_state.registry.list_agents()))
    events = get_events(limit=1)
    if events:
        st.caption(f"Data freshness: {format_timestamp(events[0].get('timestamp', 'unknown'))}")
    else:
        st.caption("Data freshness: no events yet")
    
    st.markdown("---")
    
    # Integration status
    st.markdown("**🔗 Suite Integration**")
    audit_log = resolve_suite_audit_log_path()
    if suite_integration_active():
        st.success("✅ Vestigia Connected")
        st.caption(f"Log: {audit_log}")
    else:
        st.warning("⚠️ Standalone Mode")
    
    st.markdown("---")
    
    # Auto-refresh
    st.session_state.auto_refresh = st.checkbox("Auto-Refresh", value=st.session_state.auto_refresh)

# ============================================
# MAIN DASHBOARD
# ============================================

if mode == "📊 Dashboard":
    st.title("🛡️ Tessera IAM | Operations Center")
    
    # Integration badge
    st.markdown("""
    <div class="integration-badge">
    <strong>🔗 Suite Integration Active</strong><br>
    <small>All events are logged to Vestigia audit trail</small>
    </div>
    """, unsafe_allow_html=True)
    
    # Hero metrics
    col1, col2, col3, col4 = st.columns(4)
    
    metrics = get_metrics()
    
    with col1:
        st.metric("Tokens Issued", metrics.get('tokens_issued', 0))
    
    with col2:
        denied = metrics.get('tokens_denied', 0)
        st.metric("Access Denied", denied, delta=f"{denied} blocked")
    
    with col3:
        st.metric("Validations", metrics.get('validations_allowed', 0))
    
    with col4:
        revoked = len(st.session_state.revocation_list.revoked_tokens)
        st.metric("Revoked Tokens", revoked)
    
    st.markdown("---")
    
    # Recent activity
    st.subheader("📡 Recent Activity")
    
    events = get_events(limit=10)
    
    if events:
        for event in events:
            status_class = "event-row" if event['status'] in ['success', 'granted'] else "event-row event-denied"
            emoji = "✅" if event['status'] in ['success', 'granted'] else "🚫"
            
            st.markdown(f"""
            <div class="{status_class}">
                <strong>{emoji} {event['type']}</strong> | 
                Agent: <code>{event['agent']}</code> | 
                Tool: <code>{event['tool']}</code> | 
                <span style="color: #8b949e; font-size: 0.9em;">{format_timestamp(event['timestamp'])}</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("⏳ No activity yet - Generate tokens to see events")

# ============================================
# AGENT REGISTRY
# ============================================

elif mode == "🤖 Agent Registry":
    st.header("🤖 Registered AI Agents")
    st.caption("This registry is the source of truth for identity/JIT tokens and can be imported into VerityFlux from its 'Import from Tessera' tab.")
    
    agents = st.session_state.registry.list_agents()
    
    if not agents:
        st.info("No agents registered yet")
    else:
        for agent in agents:
            with st.expander(f"🤖 {agent.agent_id} | {agent.owner}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Status:** {agent.status}")
                    st.write(f"**Risk Threshold:** {agent.risk_threshold}/100")
                    st.write(f"**Max TTL:** {agent.max_token_ttl}s")
                
                with col2:
                    st.write("**Authorized Tools:**")
                    for tool in agent.allowed_tools:
                        st.code(tool, language='text')

# ============================================
# TOKEN GENERATOR
# ============================================

elif mode == "🔑 Token Generator":
    st.header("🔑 JIT Token Issuance")
    
    agents = st.session_state.registry.list_agents(status='active')
    
    if not agents:
        st.warning("No active agents available")
    else:
        with st.form("token_form"):
            agent_id = st.selectbox("Select Agent", [a.agent_id for a in agents])
            agent = st.session_state.registry.get_agent(agent_id)
            
            if agent and agent.allowed_tools:
                tool = st.selectbox("Tool", agent.allowed_tools)
                ttl = st.slider("TTL (seconds)", 60, 3600, 300)
                
                submitted = st.form_submit_button("🔐 Generate Token", type="primary")
                
                if submitted:
                    token = st.session_state.token_gen.generate_token(agent_id, tool, custom_ttl=ttl)
                    
                    if token:
                        st.success("✅ Token Generated Successfully!")
                        st.session_state.last_generated_token = token
                        st.session_state.last_generated_tool = tool
                        st.session_state.gatekeeper_token_input = token.token
                        st.session_state.gatekeeper_tool_input = tool
                        st.session_state.token_history.insert(0, {
                            "timestamp": datetime.now().isoformat(),
                            "agent": agent_id,
                            "tool": tool,
                            "jti": token.jti,
                            "expires": token.expires_at.isoformat(),
                            "token": token.token,
                        })
                        st.session_state.token_history = st.session_state.token_history[:25]
                        
                        # 🎯 LOG TO VESTIGIA
                        add_local_event(
                            "TOKEN_ISSUED", 
                            agent_id, 
                            tool, 
                            "SUCCESS",
                            f"JTI: {token.jti}, Expires: {token.expires_at.strftime('%H:%M:%S')}"
                        )
                        
                        # Show integration confirmation
                        st.info("📝 Event logged to Vestigia audit trail")
                        
                        # Display token
                        st.markdown(f"""
                        <div class="token-display">
                        {token.token}
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.json({
                            "jti": token.jti,
                            "expires": token.expires_at.isoformat(),
                            "agent": agent_id,
                            "tool": tool
                        })
                    else:
                        st.error("Failed to generate token")
                        
                        # Log failure
                        add_local_event(
                            "TOKEN_GENERATION_FAILED",
                            agent_id,
                            tool,
                            "FAILURE",
                            "Token generation failed"
                        )

        st.markdown("---")
        st.subheader("🧾 Recently Issued Tokens (This Session)")
        if st.session_state.token_history:
            for i, entry in enumerate(st.session_state.token_history[:10], start=1):
                st.write(
                    f"{i}. `{format_timestamp(entry['timestamp'])}` | `{entry['agent']}` | "
                    f"`{entry['tool']}` | `{entry['jti']}`"
                )
            with st.expander("Show latest JWT"):
                st.code(st.session_state.token_history[0]["token"], language="text")
        else:
            st.caption("No token history yet in this UI session.")

# ============================================
# GATEKEEPER
# ============================================

elif mode == "🛡️ Gatekeeper":
    st.header("🛡️ Token Validation Gate")
    
    st.info("Enter a JWT token to validate access")

    if st.session_state.last_generated_token is not None:
        if st.button("📌 Use Latest Generated Token"):
            st.session_state.gatekeeper_token_input = st.session_state.last_generated_token.token
            if st.session_state.last_generated_tool:
                st.session_state.gatekeeper_tool_input = st.session_state.last_generated_tool
            st.rerun()

    token_input = st.text_area("JWT Token", height=100, key="gatekeeper_token_input")
    tool_input = st.text_input("Requested Tool", key="gatekeeper_tool_input")
    
    if st.button("🔍 Validate Token", type="primary"):
        if token_input and tool_input:
            result = st.session_state.gatekeeper.validate_access(token_input, tool_input)
            
            if result.decision == AccessDecision.ALLOW:
                st.success(f"✅ **ACCESS GRANTED**\n\n{result.reason}")
                
                # 🎯 LOG TO VESTIGIA
                add_local_event(
                    "TOKEN_VALIDATED", 
                    result.agent_id or "unknown", 
                    tool_input, 
                    "GRANTED",
                    f"Reason: {result.reason}"
                )
                
                st.info("📝 Validation logged to Vestigia")
                
            else:
                st.error(f"🚫 **ACCESS DENIED**\n\n{result.reason}")
                
                # 🎯 LOG TO VESTIGIA
                add_local_event(
                    "TOKEN_VALIDATION_FAILED", 
                    result.agent_id or "unknown", 
                    tool_input, 
                    "DENIED",
                    f"Reason: {result.reason}"
                )
                
                st.warning("📝 Denial logged to Vestigia")
        else:
            st.warning("Please provide both token and tool name")

# ============================================
# REVOCATION MANAGER
# ============================================

elif mode == "🚫 Revocation Manager":
    st.header("🚫 Emergency Token Revocation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Revoke Token")
        
        # Option 1: Paste full token
        token_to_revoke = st.text_area("Paste Token to Revoke", height=100)
        
        # Option 2: Enter JTI directly
        jti = st.text_input("OR Enter JWT ID (jti)")
        
        reason = st.text_input("Revocation Reason", value="Manual revocation by admin")
        
        if st.button("🚨 Emergency Revoke", type="primary"):
            # Extract JTI from token if provided
            if token_to_revoke and not jti:
                try:
                    import base64
                    # Decode JWT to get JTI (without verification)
                    parts = token_to_revoke.split('.')
                    if len(parts) >= 2:
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                        jti = payload.get('jti', '')
                except:
                    st.error("Failed to extract JTI from token")
            
            if jti:
                st.session_state.revocation_list.revoke(jti)
                
                # 🎯 LOG TO VESTIGIA
                add_local_event(
                    "TOKEN_REVOKED",
                    "SYSTEM",
                    "revocation_manager",
                    "REVOKED",
                    f"JTI: {jti}, Reason: {reason}"
                )
                
                st.error(f"✅ Token revoked!")
                st.info("📝 Revocation logged to Vestigia")
                st.code(jti, language='text')
            else:
                st.warning("Please provide a token or JTI")
    
    with col2:
        st.subheader("Blacklisted Tokens")
        
        revoked = st.session_state.revocation_list.revoked_tokens
        
        if revoked:
            st.write(f"**Total Revoked:** {len(revoked)}")
            st.markdown("---")
            for r in list(revoked)[:10]:  # Show last 10
                st.code(r, language='text')
            
            if len(revoked) > 10:
                st.caption(f"... and {len(revoked) - 10} more")
        else:
            st.info("No revoked tokens")

# ============================================
# EVENT HISTORY
# ============================================

elif mode == "📜 Event History":
    st.header("📜 Audit Trail")
    
    st.markdown("""
    <div class="integration-badge">
    <strong>🔗 Synchronized with Vestigia</strong><br>
    <small>These events are also visible in the Vestigia dashboard</small>
    </div>
    """, unsafe_allow_html=True)
    
    events = get_events(limit=100)
    
    if events:
        # Display as table
        for i, event in enumerate(events):
            col1, col2, col3, col4, col5 = st.columns([1, 2, 2, 2, 3])
            
            with col1:
                st.write(f"#{i+1}")
            with col2:
                st.write(event['type'])
            with col3:
                st.code(event['agent'], language='text')
            with col4:
                st.code(event['tool'], language='text')
            with col5:
                status_emoji = "✅" if event['status'] in ['success', 'granted', 'SUCCESS', 'GRANTED'] else "🚫"
                st.write(f"{status_emoji} {format_timestamp(event['timestamp'])}")
            if event.get('details'):
                st.caption(event['details'])
            
            if i < len(events) - 1:
                st.divider()
    else:
        st.info("No events recorded yet")

# ============================================
# BULK UPLOADS
# ============================================

elif mode == "📤 Bulk Uploads":
    st.header("📤 Bulk Uploads")
    st.caption("Upload registry/revocation data with preview-first workflow.")

    tab1, tab2 = st.tabs(["Agent Registry Upload", "Revocation Upload"])

    with tab1:
        st.write("Upload `.json` or `.csv` with fields: `agent_id, owner, tenant_id, status, allowed_tools, max_token_ttl, risk_threshold`.")
        upload = st.file_uploader("Agent file", type=["json", "csv"], key="agents_upload")
        if upload is not None:
            try:
                rows = parse_agents_upload(upload)
                st.success(f"Parsed {len(rows)} rows.")
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                apply_changes = st.checkbox("Apply changes to registry", value=False)
                if st.button("Apply Agent Upload", type="primary", disabled=not apply_changes):
                    updated = 0
                    created = 0
                    for row in rows:
                        existing = st.session_state.registry.get_agent(row["agent_id"])
                        agent = AgentIdentity(**row)
                        if existing:
                            updated += 1
                        else:
                            created += 1
                        st.session_state.registry.agents[row["agent_id"]] = agent
                    persist_registry()
                    add_local_event("AGENT_REGISTRY_BULK_UPLOAD", "SYSTEM", "registry_upload", "SUCCESS", f"created={created}, updated={updated}")
                    st.success(f"Applied upload: created {created}, updated {updated}.")
            except Exception as e:
                st.error(f"Upload validation failed: {e}")
                st.info("Fix schema/values and retry.")

    with tab2:
        st.write("Upload a text file with one JTI per line, or a JSON list of JTIs.")
        revoke_upload = st.file_uploader("Revocation file", type=["txt", "json"], key="revocations_upload")
        if revoke_upload is not None:
            try:
                raw = revoke_upload.read()
                if revoke_upload.name.lower().endswith(".json"):
                    jtIs = json.loads(raw.decode("utf-8"))
                    if not isinstance(jtIs, list):
                        raise ValueError("JSON must be a list of JTI strings.")
                    jtis = [str(x).strip() for x in jtIs if str(x).strip()]
                else:
                    text = raw.decode("utf-8")
                    jtis = [line.strip() for line in text.splitlines() if line.strip()]
                st.success(f"Parsed {len(jtis)} JTIs.")
                st.code("\n".join(jtis[:50]), language="text")
                apply_revoke = st.checkbox("Apply revocations", value=False)
                if st.button("Apply Revocations", type="primary", disabled=not apply_revoke):
                    for jti in jtis:
                        st.session_state.revocation_list.revoke(jti)
                    add_local_event("TOKEN_REVOKED_BULK_UPLOAD", "SYSTEM", "revocation_upload", "SUCCESS", f"count={len(jtis)}")
                    st.success(f"Revoked {len(jtis)} tokens.")
            except Exception as e:
                st.error(f"Upload validation failed: {e}")
                st.info("Fix file format and retry.")

# ============================================
# AUTO-REFRESH
# ============================================

if st.session_state.auto_refresh:
    time.sleep(5)
    st.rerun()

# ============================================
# FOOTER
# ============================================

st.markdown("---")
col1, col2 = st.columns(2)
with col1:
    st.caption("Tessera IAM v2.0 | Zero-Trust Identity for AI Agents")
with col2:
    if suite_integration_active():
        st.caption(f"✅ Integrated with Sovereign Security Suite")
    else:
        st.caption("⚠️ Running in standalone mode")

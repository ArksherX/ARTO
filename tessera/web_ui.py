#!/usr/bin/env python3
"""
Tessera IAM - Web Dashboard
Zero-Trust Identity & Access Management for AI Agents

Save as: web_ui/tessera_dashboard.py
Run: streamlit run web_ui/tessera_dashboard.py
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime, timedelta
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from tessera.registry import TesseraRegistry, AgentIdentity
from tessera.token_generator import TokenGenerator, TesseraToken
from tessera.gatekeeper import Gatekeeper, AccessDecision
from tessera.revocation import RevocationList

# ============================================================================
# PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="Tessera IAM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS
# ============================================================================
st.markdown("""
<style>
    /* Main theme */
    .main {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    }
    
    /* Cards */
    .tessera-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    
    .tessera-card-header {
        font-size: 1.2em;
        font-weight: bold;
        color: #58a6ff;
        margin-bottom: 10px;
    }
    
    /* Status badges */
    .status-active {
        background: #238636;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: bold;
    }
    
    .status-suspended {
        background: #f85149;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: bold;
    }
    
    .status-revoked {
        background: #6e7681;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: bold;
    }
    
    /* Tool tags */
    .tool-tag {
        background: rgba(88, 166, 255, 0.2);
        color: #58a6ff;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        margin: 2px;
        display: inline-block;
        border: 1px solid rgba(88, 166, 255, 0.3);
    }
    
    /* Token display */
    .token-display {
        background: rgba(0, 0, 0, 0.3);
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 15px;
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        color: #58a6ff;
        word-break: break-all;
        margin: 10px 0;
    }
    
    /* Metrics */
    .metric-container {
        background: rgba(88, 166, 255, 0.1);
        border-left: 4px solid #58a6ff;
        padding: 15px;
        border-radius: 4px;
        margin: 10px 0;
    }
    
    .metric-label {
        color: #8b949e;
        font-size: 0.85em;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .metric-value {
        color: #58a6ff;
        font-size: 2em;
        font-weight: bold;
        font-family: 'Courier New', monospace;
    }
    
    /* Decision badges */
    .decision-allow {
        background: #238636;
        color: white;
        padding: 8px 16px;
        border-radius: 6px;
        font-weight: bold;
        display: inline-block;
    }
    
    .decision-deny {
        background: #f85149;
        color: white;
        padding: 8px 16px;
        border-radius: 6px;
        font-weight: bold;
        display: inline-block;
    }
    
    /* Audit log */
    .audit-entry {
        background: rgba(255, 255, 255, 0.03);
        border-left: 3px solid #30363d;
        padding: 10px;
        margin: 5px 0;
        border-radius: 4px;
    }
    
    .audit-timestamp {
        color: #8b949e;
        font-size: 0.8em;
        font-family: 'Courier New', monospace;
    }
    
    /* Risk threshold indicator */
    .risk-low {
        color: #3fb950;
        font-weight: bold;
    }
    
    .risk-medium {
        color: #d29922;
        font-weight: bold;
    }
    
    .risk-high {
        color: #f85149;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# INITIALIZE SESSION STATE
# ============================================================================
if 'registry' not in st.session_state:
    st.session_state.registry = TesseraRegistry()
    
if 'token_gen' not in st.session_state:
    st.session_state.token_gen = TokenGenerator(st.session_state.registry)
    
if 'revocation_list' not in st.session_state:
    st.session_state.revocation_list = RevocationList()
    
if 'gatekeeper' not in st.session_state:
    st.session_state.gatekeeper = Gatekeeper(
        st.session_state.token_gen,
        st.session_state.revocation_list
    )

if 'audit_log' not in st.session_state:
    st.session_state.audit_log = []

if 'token_history' not in st.session_state:
    st.session_state.token_history = []

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def log_audit_event(event_type: str, agent_id: str, details: str, status: str):
    """Add entry to audit log"""
    st.session_state.audit_log.insert(0, {
        'timestamp': datetime.now(),
        'type': event_type,
        'agent_id': agent_id,
        'details': details,
        'status': status
    })
    # Keep last 100 entries
    st.session_state.audit_log = st.session_state.audit_log[:100]

def get_status_badge(status: str) -> str:
    """Get HTML badge for agent status"""
    classes = {
        'active': 'status-active',
        'suspended': 'status-suspended',
        'revoked': 'status-revoked'
    }
    return f'<span class="{classes.get(status, "status-active")}">{status.upper()}</span>'

def get_risk_class(threshold: int) -> str:
    """Get CSS class for risk threshold"""
    if threshold <= 30:
        return 'risk-high'
    elif threshold <= 60:
        return 'risk-medium'
    else:
        return 'risk-low'

def format_token_display(token: str) -> str:
    """Format token for display"""
    parts = token.split('.')
    if len(parts) == 3:
        return f"{parts[0][:20]}...{parts[0][-10:]}.{parts[1][:20]}...{parts[1][-10:]}.{parts[2][:20]}...{parts[2][-10:]}"
    return token[:50] + "..." if len(token) > 50 else token

# ============================================================================
# HEADER
# ============================================================================
st.markdown("""
<div style='text-align: center; padding: 20px; background: rgba(88, 166, 255, 0.1); border-radius: 10px; margin-bottom: 30px;'>
    <h1 style='color: #58a6ff; font-size: 3em; margin: 0;'>🛡️ Tessera IAM</h1>
    <p style='color: #8b949e; font-size: 1.2em; margin: 10px 0 0 0;'>
        Zero-Trust Identity & Access Management for AI Agents
    </p>
    <p style='color: #6e7681; font-size: 0.9em; margin: 5px 0 0 0;'>
        Cryptographic Passports • Role-Based Access Control • Just-In-Time Permissions
    </p>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# SIDEBAR
# ============================================================================
with st.sidebar:
    st.markdown("### 🎛️ Navigation")
    
    mode = st.radio(
        "Select Mode",
        [
            "📊 Dashboard",
            "🤖 Agent Registry",
            "🔑 Token Generator",
            "🛡️ Gatekeeper",
            "🚫 Revocation Manager",
            "📜 Audit Log"
        ],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    st.markdown("### 📈 System Metrics")
    
    total_agents = len(st.session_state.registry.list_agents())
    active_agents = len(st.session_state.registry.list_agents(status='active'))
    total_tokens = len(st.session_state.token_history)
    revoked_tokens = len(st.session_state.revocation_list.revoked_tokens)
    
    st.metric("Total Agents", total_agents)
    st.metric("Active Agents", active_agents, 
              delta=f"{active_agents - (total_agents - active_agents)} more")
    st.metric("Tokens Issued", total_tokens)
    st.metric("Revoked Tokens", revoked_tokens)
    
    st.markdown("---")
    st.markdown("### ⚙️ System Status")
    st.markdown("✅ Registry: **Online**")
    st.markdown("✅ Token Generator: **Ready**")
    st.markdown("✅ Gatekeeper: **Active**")
    st.markdown("✅ Revocation List: **Synced**")

# ============================================================================
# MODE: DASHBOARD
# ============================================================================
if mode == "📊 Dashboard":
    st.header("📊 Security Dashboard")
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class='metric-container'>
            <div class='metric-label'>Total Agents</div>
            <div class='metric-value'>{}</div>
        </div>
        """.format(total_agents), unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='metric-container'>
            <div class='metric-label'>Active Agents</div>
            <div class='metric-value'>{}</div>
        </div>
        """.format(active_agents), unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class='metric-container'>
            <div class='metric-label'>Tokens Issued</div>
            <div class='metric-value'>{}</div>
        </div>
        """.format(total_tokens), unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class='metric-container'>
            <div class='metric-label'>Revoked Tokens</div>
            <div class='metric-value'>{}</div>
        </div>
        """.format(revoked_tokens), unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Agent status distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🤖 Agent Status Distribution")
        agents = st.session_state.registry.list_agents()
        status_counts = {}
        for agent in agents:
            status_counts[agent.status] = status_counts.get(agent.status, 0) + 1
        
        if status_counts:
            fig = go.Figure(data=[go.Pie(
                labels=list(status_counts.keys()),
                values=list(status_counts.values()),
                hole=0.4,
                marker=dict(colors=['#238636', '#f85149', '#6e7681'])
            )])
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#c9d1d9'),
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No agents registered yet")
    
    with col2:
        st.subheader("🔑 Token Activity (Last 24h)")
        
        # Simulate token activity data
        if st.session_state.token_history:
            recent_tokens = [t for t in st.session_state.token_history 
                           if (datetime.now() - t['timestamp']).days == 0]
            
            if recent_tokens:
                hourly_counts = {}
                for token in recent_tokens:
                    hour = token['timestamp'].hour
                    hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
                
                fig = go.Figure(data=[go.Bar(
                    x=list(hourly_counts.keys()),
                    y=list(hourly_counts.values()),
                    marker=dict(color='#58a6ff')
                )])
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#c9d1d9'),
                    xaxis_title="Hour",
                    yaxis_title="Tokens Issued",
                    height=300
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No tokens issued in the last 24 hours")
        else:
            st.info("No token history yet")
    
    st.markdown("---")
    
    # Recent activity
    st.subheader("📜 Recent Activity")
    
    if st.session_state.audit_log:
        for entry in st.session_state.audit_log[:10]:
            status_emoji = "✅" if entry['status'] == 'success' else "❌"
            st.markdown(f"""
            <div class='audit-entry'>
                <div style='display: flex; justify-content: space-between;'>
                    <span>{status_emoji} <strong>{entry['type']}</strong> - {entry['agent_id']}</span>
                    <span class='audit-timestamp'>{entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                <div style='color: #8b949e; font-size: 0.9em; margin-top: 5px;'>{entry['details']}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No recent activity")

# ============================================================================
# MODE: AGENT REGISTRY
# ============================================================================
elif mode == "🤖 Agent Registry":
    st.header("🤖 Agent Registry")
    
    tab1, tab2 = st.tabs(["📋 View Agents", "➕ Register New Agent"])
    
    with tab1:
        st.subheader("Registered Agents")
        
        # Filter
        filter_status = st.selectbox(
            "Filter by Status",
            ["All", "active", "suspended", "revoked"]
        )
        
        agents = st.session_state.registry.list_agents()
        if filter_status != "All":
            agents = [a for a in agents if a.status == filter_status]
        
        if agents:
            for agent in agents:
                with st.expander(f"🤖 {agent.agent_id} ({agent.owner})"):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"""
                        <div class='tessera-card'>
                            <div class='tessera-card-header'>Agent Details</div>
                            <p><strong>Agent ID:</strong> <code>{agent.agent_id}</code></p>
                            <p><strong>Owner:</strong> {agent.owner}</p>
                            <p><strong>Status:</strong> {get_status_badge(agent.status)}</p>
                            <p><strong>Max Token TTL:</strong> {agent.max_token_ttl}s</p>
                            <p><strong>Risk Threshold:</strong> 
                               <span class='{get_risk_class(agent.risk_threshold)}'>{agent.risk_threshold}/100</span>
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.markdown("**Allowed Tools:**")
                        for tool in agent.allowed_tools:
                            st.markdown(f'<span class="tool-tag">{tool}</span>', unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown("**Actions:**")
                        
                        if agent.status == 'active':
                            if st.button("🚫 Suspend", key=f"suspend_{agent.agent_id}"):
                                st.session_state.registry.update_agent(agent.agent_id, status='suspended')
                                log_audit_event("AGENT_SUSPENDED", agent.agent_id, 
                                              "Agent suspended by administrator", "success")
                                st.rerun()
                        else:
                            if st.button("✅ Activate", key=f"activate_{agent.agent_id}"):
                                st.session_state.registry.update_agent(agent.agent_id, status='active')
                                log_audit_event("AGENT_ACTIVATED", agent.agent_id,
                                              "Agent activated by administrator", "success")
                                st.rerun()
                        
                        if st.button("🔴 Revoke", key=f"revoke_{agent.agent_id}"):
                            st.session_state.registry.revoke_agent(agent.agent_id)
                            log_audit_event("AGENT_REVOKED", agent.agent_id,
                                          "Agent permanently revoked", "success")
                            st.rerun()
        else:
            st.info("No agents match the filter criteria")
    
    with tab2:
        st.subheader("Register New Agent")
        
        with st.form("register_agent"):
            agent_id = st.text_input("Agent ID", placeholder="agent_example_01")
            owner = st.text_input("Owner", placeholder="Department/Team")
            
            allowed_tools = st.text_area(
                "Allowed Tools (one per line)",
                placeholder="read_csv\nquery_sql\nsend_email"
            )
            
            col1, col2 = st.columns(2)
            with col1:
                max_ttl = st.number_input("Max Token TTL (seconds)", 
                                         min_value=30, max_value=3600, value=300)
            with col2:
                risk_threshold = st.slider("Risk Threshold", 0, 100, 50)
            
            submitted = st.form_submit_button("Register Agent")
            
            if submitted:
                if not agent_id or not owner or not allowed_tools:
                    st.error("All fields are required")
                else:
                    tools_list = [t.strip() for t in allowed_tools.split('\n') if t.strip()]
                    
                    new_agent = AgentIdentity(
                        agent_id=agent_id,
                        owner=owner,
                        allowed_tools=tools_list,
                        max_token_ttl=max_ttl,
                        risk_threshold=risk_threshold,
                        status='active'
                    )
                    
                    success = st.session_state.registry.register_agent(new_agent)
                    
                    if success:
                        st.success(f"✅ Agent {agent_id} registered successfully!")
                        log_audit_event("AGENT_REGISTERED", agent_id,
                                      f"New agent registered by {owner}", "success")
                        st.rerun()
                    else:
                        st.error(f"❌ Agent {agent_id} already exists")

# ============================================================================
# MODE: TOKEN GENERATOR
# ============================================================================
elif mode == "🔑 Token Generator":
    st.header("🔑 Token Generator")
    
    st.markdown("""
    Generate Just-In-Time (JIT) cryptographic passports for agent tool access.
    Each token is valid for a limited time and grants access to a specific tool.
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Request Token")
        
        with st.form("generate_token"):
            agents = st.session_state.registry.list_agents(status='active')
            agent_options = {f"{a.agent_id} ({a.owner})": a.agent_id for a in agents}
            
            if not agents:
                st.warning("No active agents available")
            else:
                selected = st.selectbox("Select Agent", list(agent_options.keys()))
                agent_id = agent_options[selected]
                
                agent = st.session_state.registry.get_agent(agent_id)
                
                st.markdown("**Available Tools:**")
                tool = st.selectbox("Select Tool", agent.allowed_tools)
                
                custom_ttl = st.checkbox("Custom TTL")
                if custom_ttl:
                    ttl = st.number_input("TTL (seconds)", 
                                         min_value=30, 
                                         max_value=agent.max_token_ttl,
                                         value=agent.max_token_ttl)
                else:
                    ttl = None
                
                submitted = st.form_submit_button("🔑 Generate Token", type="primary")
                
                if submitted:
                    token = st.session_state.token_gen.generate_token(
                        agent_id, tool, custom_ttl=ttl
                    )
                    
                    if token:
                        st.session_state.token_history.append({
                            'timestamp': datetime.now(),
                            'agent_id': agent_id,
                            'tool': tool,
                            'jti': token.jti,
                            'token': token.token
                        })
                        
                        log_audit_event("TOKEN_ISSUED", agent_id,
                                      f"Token issued for tool: {tool}", "success")
                        
                        st.session_state.generated_token = token
                        st.rerun()
                    else:
                        st.error("❌ Failed to generate token")
    
    with col2:
        st.subheader("Generated Token")
        
        if 'generated_token' in st.session_state:
            token = st.session_state.generated_token
            
            st.markdown(f"""
            <div class='tessera-card'>
                <div class='tessera-card-header'>✅ Token Generated Successfully</div>
                <p><strong>Agent:</strong> {token.agent_id}</p>
                <p><strong>Tool:</strong> <code>{token.tool}</code></p>
                <p><strong>Issued:</strong> {token.issued_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Expires:</strong> {token.expires_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Risk Threshold:</strong> {token.risk_threshold}/100</p>
                <p><strong>JWT ID:</strong> <code>{token.jti}</code></p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("**Token:**")
            st.code(token.token, language='text')
            
            st.download_button(
                "📥 Download Token",
                token.token,
                file_name=f"tessera_token_{token.jti}.jwt",
                mime="text/plain"
            )
            
            if st.button("🗑️ Clear"):
                del st.session_state.generated_token
                st.rerun()
        else:
            st.info("No token generated yet. Use the form to generate a token.")

# ============================================================================
# MODE: GATEKEEPER
# ============================================================================
elif mode == "🛡️ Gatekeeper":
    st.header("🛡️ Gatekeeper - Token Validation")
    
    st.markdown("""
    Validate agent access requests. The Gatekeeper verifies token authenticity,
    checks revocation status, and ensures scope alignment.
    """)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Validate Access Request")
        
        with st.form("validate_access"):
            token_input = st.text_area(
                "Tessera Token (JWT)",
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                height=150
            )
            
            requested_tool = st.text_input(
                "Requested Tool",
                placeholder="e.g., read_csv"
            )
            
            submitted = st.form_submit_button("🔍 Validate", type="primary")
            
            if submitted:
                if not token_input or not requested_tool:
                    st.error("Both token and tool are required")
                else:
                    result = st.session_state.gatekeeper.validate_access(
                        token_input.strip(), 
                        requested_tool.strip()
                    )
                    
                    st.session_state.validation_result = result
                    
                    # Log the validation attempt
                    agent_id = result.agent_id or "unknown"
                    status = "success" if result.decision == AccessDecision.ALLOW else "denied"
                    log_audit_event("ACCESS_VALIDATION", agent_id,
                                  f"Tool: {requested_tool} - {result.reason}", status)
                    
                    st.rerun()
    
    with col2:
        st.subheader("Validation Result")
        
        if 'validation_result' in st.session_state:
            result = st.session_state.validation_result
            
            if result.decision == AccessDecision.ALLOW:
                st.markdown("""
                <div class='tessera-card' style='border-left: 4px solid #238636;'>
                    <h2 style='color: #3fb950;'>✅ ACCESS GRANTED</h2>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div class='tessera-card'>
                    <p><strong>Agent ID:</strong> {result.agent_id}</p>
                    <p><strong>Tool:</strong> <code>{result.tool}</code></p>
                    <p><strong>Risk Threshold:</strong> {result.risk_threshold}/100</p>
                    <p><strong>Reason:</strong> {result.reason}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class='tessera-card' style='border-left: 4px solid #f85149;'>
                    <h2 style='color: #f85149;'>🚫 ACCESS DENIED</h2>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div class='tessera-card'>
                    <p><strong>Decision:</strong> {result.decision.value.upper().replace('_', ' ')}</p>
                    <p><strong>Reason:</strong> {result.reason}</p>
                    {f'<p><strong>Agent ID:</strong> {result.agent_id}</p>' if result.agent_id else ''}
                </div>
                """, unsafe_allow_html=True)
            
            if st.button("🗑️ Clear Result"):
                del st.session_state.validation_result
                st.rerun()
        else:
            st.info("No validation performed yet. Submit a token to validate.")

# ============================================================================
# MODE: REVOCATION MANAGER
# ============================================================================
elif mode == "🚫 Revocation Manager":
    st.header("🚫 Revocation Manager")
    
    st.markdown("""
    Manage revoked tokens. Revoking a token immediately invalidates it,
    preventing further use even if it hasn't expired.
    """)
    
    tab1, tab2 = st.tabs(["📋 Revoked Tokens", "🔴 Revoke Token"])
    
    with tab1:
        st.subheader("Revoked Token List")
        
        if st.session_state.revocation_list.revoked_tokens:
            for jti in st.session_state.revocation_list.revoked_tokens:
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"""
                    <div class='audit-entry'>
                        <code>{jti}</code>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    if st.button("♻️ Unrevoke", key=f"unrevoke_{jti}"):
                        st.session_state.revocation_list.unrevoke(jti)
                        log_audit_event("TOKEN_UNREVOKED", "system",
                                      f"Token {jti} unrevoked", "success")
                        st.rerun()
        else:
            st.info("No revoked tokens")
    
    with tab2:
        st.subheader("Revoke Token")
        
        st.markdown("Enter the JWT ID (jti) of the token to revoke:")
        
        with st.form("revoke_token"):
            jti_input = st.text_input("JWT ID (jti)", placeholder="tessera_abc123...")
            
            # Show recent tokens for convenience
            if st.session_state.token_history:
                st.markdown("**Recent Tokens:**")
                recent = st.session_state.token_history[-5:]
                for t in reversed(recent):
                    if st.checkbox(f"{t['jti']} ({t['agent_id']} - {t['tool']})", 
                                 key=f"recent_{t['jti']}"):
                        jti_input = t['jti']
            
            submitted = st.form_submit_button("🔴 Revoke Token", type="primary")
            
            if submitted:
                if not jti_input:
                    st.error("JWT ID is required")
                else:
                    st.session_state.revocation_list.revoke(jti_input.strip())
                    log_audit_event("TOKEN_REVOKED", "system",
                                  f"Token {jti_input} manually revoked", "success")
                    st.success(f"✅ Token {jti_input} has been revoked")
                    st.rerun()

# ============================================================================
# MODE: AUDIT LOG
# ============================================================================
elif mode == "📜 Audit Log":
    st.header("📜 Audit Log")
    
    st.markdown("""
    Complete audit trail of all Tessera IAM operations.
    """)
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_type = st.selectbox(
            "Event Type",
            ["All"] + list(set([e['type'] for e in st.session_state.audit_log]))
        )
    
    with col2:
        filter_status = st.selectbox(
            "Status",
            ["All", "success", "denied"]
        )
    
    with col3:
        limit = st.number_input("Show entries", min_value=10, max_value=100, value=50)
    
    # Filter logs
    filtered_logs = st.session_state.audit_log
    
    if filter_type != "All":
        filtered_logs = [e for e in filtered_logs if e['type'] == filter_type]
    
    if filter_status != "All":
        filtered_logs = [e for e in filtered_logs if e['status'] == filter_status]
    
    filtered_logs = filtered_logs[:limit]
    
    # Display logs
    if filtered_logs:
        for entry in filtered_logs:
            status_emoji = "✅" if entry['status'] == 'success' else "❌"
            
            st.markdown(f"""
            <div class='audit-entry'>
                <div style='display: flex; justify-content: space-between; align-items: center;'>
                    <div>
                        <span style='font-size: 1.2em;'>{status_emoji}</span>
                        <strong style='color: #58a6ff;'>{entry['type']}</strong>
                        <span style='color: #8b949e;'>—</span>
                        <code>{entry['agent_id']}</code>
                    </div>
                    <span class='audit-timestamp'>{entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                <div style='color: #8b949e; font-size: 0.9em; margin-top: 8px; padding-left: 30px;'>
                    {entry['details']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Export option
        st.markdown("---")
        if st.button("📥 Export Audit Log"):
            df = pd.DataFrame(filtered_logs)
            csv = df.to_csv(index=False)
            st.download_button(
                "Download CSV",
                csv,
                file_name=f"tessera_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No audit entries match the filter criteria")

# ============================================================================
# FOOTER
# ============================================================================
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #6e7681; font-size: 0.9em;'>
    <p>🛡️ <strong>Tessera IAM</strong> | Zero-Trust Identity Management for AI Agents</p>
    <p>Version 1.0.0 | Built for DEF CON Singapore 2026</p>
</div>
""", unsafe_allow_html=True)

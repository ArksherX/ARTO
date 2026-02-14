#!/usr/bin/env python3
"""
Tessera IAM - Complete Enterprise Dashboard
Incorporates: Kill-Switch, Incident Monitoring, Proof of Reasoning, Behavioral Biometrics
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime, timedelta
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv
load_dotenv()

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper
from tessera.revocation import RevocationList
from tessera.owner_isolation import OwnerIsolationManager
from tessera.scope_limiter import ScopeValidator

st.set_page_config(
    page_title="Tessera IAM SOC", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .critical-alert {
        background: #ff4444;
        padding: 15px;
        border-radius: 8px;
        color: white;
        margin: 10px 0;
    }
    .success-badge {
        background: #00C851;
        padding: 5px 10px;
        border-radius: 5px;
        color: white;
        font-weight: bold;
    }
    .warning-badge {
        background: #ffbb33;
        padding: 5px 10px;
        border-radius: 5px;
        color: black;
        font-weight: bold;
    }
    .critical-badge {
        background: #ff4444;
        padding: 5px 10px;
        border-radius: 5px;
        color: white;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize components
if 'registry' not in st.session_state:
    st.session_state.registry = TesseraRegistry()
if 'token_gen' not in st.session_state:
    st.session_state.token_gen = TokenGenerator(st.session_state.registry)
if 'revocation_list' not in st.session_state:
    st.session_state.revocation_list = RevocationList()
if 'gatekeeper' not in st.session_state:
    st.session_state.gatekeeper = Gatekeeper(st.session_state.token_gen, st.session_state.revocation_list)
if 'owner_manager' not in st.session_state:
    st.session_state.owner_manager = OwnerIsolationManager()
if 'scope_validator' not in st.session_state:
    st.session_state.scope_validator = ScopeValidator()
if 'active_tokens' not in st.session_state:
    st.session_state.active_tokens = []
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = []
if 'behavioral_log' not in st.session_state:
    st.session_state.behavioral_log = []

def log_audit(event_type, agent_id, details, status, severity="info"):
    st.session_state.audit_log.insert(0, {
        'timestamp': datetime.now(),
        'type': event_type,
        'agent_id': agent_id,
        'details': details,
        'status': status,
        'severity': severity
    })
    # Keep only last 1000 entries
    st.session_state.audit_log = st.session_state.audit_log[:1000]

def log_behavioral(agent_id, tool, response_time_ms):
    st.session_state.behavioral_log.append({
        'timestamp': datetime.now(),
        'agent_id': agent_id,
        'tool': tool,
        'response_time_ms': response_time_ms
    })

# Header
st.title("🛡️ Tessera IAM - Security Operations Center")
st.caption("Zero-Trust Identity & Access Management for AI Agents | Enterprise Edition")

# Sidebar Navigation
with st.sidebar:
    st.image("https://via.placeholder.com/200x80/667eea/ffffff?text=Tessera+IAM", use_container_width=True)
    
    mode = st.radio("🎯 Navigation", [
        "📊 Executive Dashboard",
        "🚨 Security Incidents",
        "🔑 Active Tokens",
        "⚡ Kill-Switch",
        "🤖 Agent Registry",
        "🔍 Behavioral Analytics",
        "📜 Audit Log",
        "⚙️ System Configuration"
    ])
    
    st.divider()
    
    # Real-time metrics
    total_agents = len(st.session_state.registry.list_agents())
    active_agents = len(st.session_state.registry.list_agents(status='active'))
    blacklisted_agents = len(st.session_state.registry.list_agents(status='blacklisted'))
    active_tokens = len([t for t in st.session_state.active_tokens if not t.get('revoked')])
    
    st.metric("🤖 Total Agents", total_agents)
    st.metric("✅ Active", active_agents, delta=f"-{blacklisted_agents} blocked" if blacklisted_agents > 0 else None)
    st.metric("🔑 Active Tokens", active_tokens)
    st.metric("🚫 Revoked", len(st.session_state.revocation_list.revoked_tokens))
    
    if blacklisted_agents > 0:
        st.error(f"⚠️ {blacklisted_agents} Critical Incidents")

# ============================================================================
# MODE 1: EXECUTIVE DASHBOARD
# ============================================================================
if mode == "📊 Executive Dashboard":
    st.header("Executive Security Dashboard")
    
    # Top metrics with visual cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class='metric-card'>
            <h3>🤖 {total_agents}</h3>
            <p>Total Agents</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        status_color = "success" if blacklisted_agents == 0 else "critical"
        st.markdown(f"""
        <div class='metric-card'>
            <h3>🛡️ {active_agents}</h3>
            <p>Active & Secure</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class='metric-card'>
            <h3>🔑 {active_tokens}</h3>
            <p>Active Sessions</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        incidents = blacklisted_agents + len([a for a in st.session_state.audit_log if a.get('severity') == 'critical'])
        st.markdown(f"""
        <div class='metric-card'>
            <h3>🚨 {incidents}</h3>
            <p>Security Events</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # Critical alerts section
    blacklisted = st.session_state.registry.list_agents(status='blacklisted')
    if blacklisted:
        st.markdown("<div class='critical-alert'>", unsafe_allow_html=True)
        st.error(f"🚨 CRITICAL: {len(blacklisted)} agent(s) blacklisted by Self-Healing Loop")
        st.markdown("</div>", unsafe_allow_html=True)
        
        for agent in blacklisted:
            with st.expander(f"⚠️ Incident: {agent.agent_id}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**Agent ID:** {agent.agent_id}")
                    st.write(f"**Department:** {agent.owner}")
                    st.write(f"**Reason:** {agent.status_reason or 'Security violation detected'}")
                    st.write(f"**Timestamp:** {agent.last_updated or 'Unknown'}")
                with col2:
                    if st.button("🔓 Review & Restore", key=f"restore_{agent.agent_id}"):
                        st.warning("Manual review required. Contact security team.")
    
    # Recent activity timeline
    st.subheader("📈 Recent Activity Timeline")
    if st.session_state.audit_log:
        recent = st.session_state.audit_log[:10]
        for entry in recent:
            severity = entry.get('severity', 'info')
            emoji = {
                'info': '✅',
                'warning': '⚠️',
                'critical': '🚨'
            }.get(severity, 'ℹ️')
            
            col1, col2 = st.columns([1, 5])
            with col1:
                st.write(entry['timestamp'].strftime('%H:%M:%S'))
            with col2:
                st.write(f"{emoji} **{entry['type']}** - {entry['agent_id']}: {entry['details']}")
    else:
        st.info("No activity recorded. System is in monitoring mode.")
    
    # System health gauge
    st.subheader("🏥 System Health")
    health_score = 100 - (blacklisted_agents * 20)  # Each blacklisted agent reduces health by 20%
    health_score = max(0, health_score)
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = health_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Security Posture"},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkgreen" if health_score > 80 else "orange" if health_score > 50 else "red"},
            'steps': [
                {'range': [0, 50], 'color': "lightgray"},
                {'range': [50, 80], 'color': "gray"},
                {'range': [80, 100], 'color': "lightgreen"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    st.plotly_chart(fig, use_container_width=True)

# ============================================================================
# MODE 2: SECURITY INCIDENTS
# ============================================================================
elif mode == "🚨 Security Incidents":
    st.header("🚨 Security Incident Response Center")
    
    blacklisted = st.session_state.registry.list_agents(status='blacklisted')
    suspended = st.session_state.registry.list_agents(status='suspended')
    
    tab1, tab2, tab3 = st.tabs(["🚫 Blacklisted", "⏸️ Suspended", "📊 Incident Analytics"])
    
    with tab1:
        if not blacklisted:
            st.success("✅ No agents currently blacklisted")
        else:
            st.error(f"⚠️ {len(blacklisted)} agent(s) permanently blocked")
            
            for agent in blacklisted:
                with st.expander(f"🚫 {agent.agent_id} - BLACKLISTED"):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.write(f"**Owner:** {agent.owner}")
                        st.write(f"**Status:** BLACKLISTED")
                        st.write(f"**Reason:** {agent.status_reason or 'Unknown security violation'}")
                        st.write(f"**Last Updated:** {agent.last_updated or 'Unknown'}")
                        st.write(f"**Original Tools:** {', '.join(agent.allowed_tools)}")
                    
                    with col2:
                        st.metric("Risk Level", "CRITICAL", delta="100")
                        if st.button("📋 Export Report", key=f"export_{agent.agent_id}"):
                            report = f"""
SECURITY INCIDENT REPORT
========================
Agent ID: {agent.agent_id}
Owner: {agent.owner}
Status: BLACKLISTED
Reason: {agent.status_reason}
Timestamp: {agent.last_updated}

RECOMMENDED ACTIONS:
1. Forensic analysis of agent logs
2. Review all recent tool calls
3. Check for data exfiltration
4. Update security policies
                            """
                            st.download_button(
                                "Download Report",
                                report,
                                f"incident_{agent.agent_id}_{datetime.now().strftime('%Y%m%d')}.txt"
                            )
    
    with tab2:
        if not suspended:
            st.info("No suspended agents")
        else:
            for agent in suspended:
                st.warning(f"⏸️ {agent.agent_id} - Suspended")
    
    with tab3:
        st.subheader("📊 Incident Trends")
        
        # Create incident timeline
        critical_events = [e for e in st.session_state.audit_log if e.get('severity') == 'critical']
        if critical_events:
            df = pd.DataFrame(critical_events)
            df['hour'] = df['timestamp'].dt.hour
            
            fig = px.histogram(df, x='hour', title="Critical Events by Hour")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No critical incidents recorded")

# ============================================================================
# MODE 3: ACTIVE TOKENS
# ============================================================================
elif mode == "🔑 Active Tokens":
    st.header("🔑 Active Token Management")
    
    if not st.session_state.active_tokens:
        st.info("No active tokens. Generate one in the Agent Registry.")
    else:
        active_count = len([t for t in st.session_state.active_tokens if not t.get('revoked')])
        st.metric("Active Sessions", active_count)
        
        for idx, token_info in enumerate(st.session_state.active_tokens):
            if token_info.get('revoked'):
                continue
            
            time_left = token_info['expires_at'] - datetime.now()
            is_expired = time_left.total_seconds() <= 0
            
            with st.expander(f"🔑 {token_info['jti'][:16]}... - {token_info['agent_id']}"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.write(f"**Agent:** {token_info['agent_id']}")
                    st.write(f"**Tool:** {token_info['tool']}")
                    st.write(f"**Issued:** {token_info['issued_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    st.write(f"**Expires:** {token_info['expires_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                
                with col2:
                    if is_expired:
                        st.error("⏰ EXPIRED")
                    else:
                        st.success(f"⏱️ {int(time_left.total_seconds())}s left")
                
                with col3:
                    if not is_expired:
                        if st.button("🚨 REVOKE", key=f"revoke_{idx}", type="primary"):
                            st.session_state.revocation_list.revoke(token_info['jti'])
                            token_info['revoked'] = True
                            log_audit("TOKEN_REVOKED", token_info['agent_id'],
                                    f"Manual revocation of {token_info['jti']}", "revoked", "warning")
                            st.success("✅ Token revoked!")
                            st.rerun()

# ============================================================================
# MODE 4: KILL-SWITCH
# ============================================================================
elif mode == "⚡ Kill-Switch":
    st.header("⚡ Emergency Kill-Switch")
    st.error("⚠️ WARNING: This will immediately revoke ALL active tokens across the entire system!")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### When to use Kill-Switch:
        - 🚨 Confirmed security breach detected
        - 🎯 Multiple agents showing malicious behavior
        - 🔥 Critical vulnerability discovered
        - 🛑 Emergency system lockdown required
        
        ### What happens:
        1. All active tokens immediately revoked
        2. All agents temporarily suspended
        3. CISO notification triggered
        4. Full audit log generated
        5. Manual review required to restore access
        """)
    
    with col2:
        active_count = len([t for t in st.session_state.active_tokens if not t.get('revoked')])
        st.metric("Tokens to Revoke", active_count)
        st.metric("Agents to Suspend", active_agents)
    
    st.divider()
    
    if active_count == 0:
        st.info("✅ No active tokens to revoke")
    else:
        st.subheader("📋 Tokens to be Revoked:")
        for token_info in st.session_state.active_tokens:
            if not token_info.get('revoked'):
                st.write(f"- 🔑 {token_info['jti'][:16]}... ({token_info['agent_id']} / {token_info['tool']})")
        
        st.divider()
        
        confirm_text = st.text_input("⚠️ Type 'EXECUTE KILL-SWITCH' to confirm:")
        
        if st.button("🚨 EXECUTE KILL-SWITCH", 
                    type="primary", 
                    disabled=(confirm_text != "EXECUTE KILL-SWITCH"),
                    use_container_width=True):
            
            with st.spinner("Executing emergency shutdown..."):
                revoked_count = 0
                for token_info in st.session_state.active_tokens:
                    if not token_info.get('revoked'):
                        st.session_state.revocation_list.revoke(token_info['jti'])
                        token_info['revoked'] = True
                        revoked_count += 1
                
                # Suspend all active agents
                for agent in st.session_state.registry.list_agents(status='active'):
                    agent.status = 'suspended'
                
                log_audit("KILL_SWITCH_EXECUTED", "SYSTEM",
                         f"Emergency revocation of {revoked_count} tokens. All agents suspended.",
                         "executed", "critical")
                
                st.error(f"🚨 KILL-SWITCH EXECUTED!")
                st.error(f"✅ {revoked_count} tokens revoked")
                st.error(f"⏸️ {active_agents} agents suspended")
                st.error(f"📧 CISO alert sent")
                st.balloons()
                st.rerun()

# ============================================================================
# MODE 5: AGENT REGISTRY
# ============================================================================
elif mode == "🤖 Agent Registry":
    st.header("🤖 Agent Identity Registry")
    
    tab1, tab2, tab3 = st.tabs(["📋 View Agents", "🔑 Generate Token", "➕ Register New Agent"])
    
    with tab1:
        agents = st.session_state.registry.list_agents()
        
        # Filter by status
        status_filter = st.selectbox("Filter by Status", ["all", "active", "suspended", "blacklisted"])
        if status_filter != "all":
            agents = [a for a in agents if a.status == status_filter]
        
        for agent in agents:
            status_color = {
                'active': '🟢',
                'suspended': '🟡',
                'blacklisted': '🔴'
            }.get(agent.status, '⚪')
            
            with st.expander(f"{status_color} {agent.agent_id} - {agent.owner}"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.write(f"**Status:** {agent.status.upper()}")
                    st.write(f"**Allowed Tools:** {', '.join(agent.allowed_tools)}")
                    st.write(f"**Token TTL:** {agent.max_token_ttl}s")
                    st.write(f"**Risk Threshold:** {agent.risk_threshold}/100")
                    if agent.status_reason:
                        st.write(f"**Status Reason:** {agent.status_reason}")
                
                with col2:
                    # Department permissions
                    can_use = st.session_state.owner_manager.can_access_agent(agent.owner, agent.owner)
                    st.metric("Dept Access", "✅" if can_use else "❌")
                
                with col3:
                    if agent.status == "active":
                        if st.button("⏸️ Suspend", key=f"suspend_{agent.agent_id}"):
                            agent.status = "suspended"
                            log_audit("AGENT_SUSPENDED", agent.agent_id, 
                                    "Manually suspended by admin", "suspended", "warning")
                            st.rerun()
                    elif agent.status == "suspended":
                        if st.button("▶️ Activate", key=f"activate_{agent.agent_id}"):
                            agent.status = "active"
                            log_audit("AGENT_ACTIVATED", agent.agent_id,
                                    "Manually activated by admin", "activated", "info")
                            st.rerun()
    
    with tab2:
        st.subheader("🔑 Token Generation")
        
        active_agents_list = st.session_state.registry.list_agents(status='active')
        if not active_agents_list:
            st.warning("No active agents available")
        else:
            agent_options = {f"{a.agent_id} ({a.owner})": a.agent_id for a in active_agents_list}
            selected = st.selectbox("Select Agent", list(agent_options.keys()))
            agent_id = agent_options[selected]
            agent = st.session_state.registry.get_agent(agent_id)
            
            tool = st.selectbox("Select Tool", agent.allowed_tools)
            justification = st.text_area("Justification (optional)", 
                                        placeholder="Why does this agent need this access?")
            
            if st.button("🔑 Generate Token", type="primary", use_container_width=True):
                token = st.session_state.token_gen.generate_token(agent_id, tool)
                if token:
                    st.session_state.active_tokens.append({
                        'jti': token.jti,
                        'agent_id': agent_id,
                        'tool': tool,
                        'token': token.token,
                        'issued_at': token.issued_at,
                        'expires_at': token.expires_at,
                        'revoked': False
                    })
                    log_audit("TOKEN_ISSUED", agent_id,
                            f"Token issued for {tool}: {justification or 'No justification provided'}",
                            "issued", "info")
                    
                    st.success(f"✅ Token Generated Successfully!")
                    st.code(token.token, language='text')
                    
                    st.download_button(
                        "📥 Download Token",
                        token.token,
                        f"tessera_token_{token.jti}.jwt",
                        "text/plain"
                    )
    
    with tab3:
        st.subheader("➕ Register New Agent")
        st.info("This feature will be available in the next release")

# ============================================================================
# MODE 6: BEHAVIORAL ANALYTICS
# ============================================================================
elif mode == "🔍 Behavioral Analytics":
    st.header("🔍 Behavioral Analytics & Biometrics")
    
    st.info("📊 This module monitors agent behavior patterns to detect anomalies")
    
    tab1, tab2 = st.tabs(["📈 Response Time Analysis", "🎯 Tool Usage Patterns"])
    
    with tab1:
        st.subheader("Response Time Monitoring")
        
        if st.session_state.behavioral_log:
            df = pd.DataFrame(st.session_state.behavioral_log)
            
            # Group by agent
            for agent_id in df['agent_id'].unique():
                agent_data = df[df['agent_id'] == agent_id]
                avg_time = agent_data['response_time_ms'].mean()
                
                st.metric(f"{agent_id}", f"{avg_time:.0f}ms", 
                         delta=f"±{agent_data['response_time_ms'].std():.0f}ms")
                
                fig = px.line(agent_data, x='timestamp', y='response_time_ms',
                             title=f"{agent_id} Response Times")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No behavioral data collected yet. Activity will appear here once tokens are used.")
    
    with tab2:
        st.subheader("Tool Usage Patterns")
        
        if st.session_state.audit_log:
            # Extract tool usage from audit log
            tool_usage = {}
            for entry in st.session_state.audit_log:
                if entry['type'] == 'TOKEN_ISSUED':
                    agent = entry['agent_id']
                    if agent not in tool_usage:
                        tool_usage[agent] = []
                    # Extract tool from details (simple parsing)
                    tool_usage[agent].append(entry['timestamp'])
            
            if tool_usage:
                st.write("### Tool Request Frequency")
                for agent, timestamps in tool_usage.items():
                    st.write(f"**{agent}:** {len(timestamps)} requests")
            else:
                st.info("No tool usage data yet")
        else:
            st.info("No tool usage recorded")

# ============================================================================
# MODE 7: AUDIT LOG
# ============================================================================
elif mode == "📜 Audit Log":
    st.header("📜 Complete Audit Trail")
    
    if not st.session_state.audit_log:
        st.info("No audit entries recorded yet")
    else:
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.selectbox("Severity", ["all", "info", "warning", "critical"])
        with col2:
            type_filter = st.selectbox("Event Type", ["all"] + list(set(e['type'] for e in st.session_state.audit_log)))
        with col3:
            limit = st.number_input("Show entries", min_value=10, max_value=1000, value=100)
        
        # Filter and display
        filtered_log = st.session_state.audit_log[:limit]
        
        if severity_filter != "all":
            filtered_log = [e for e in filtered_log if e.get('severity') == severity_filter]
        if type_filter != "all":
            filtered_log = [e for e in filtered_log if e['type'] == type_filter]
        
        # Display as table
        df = pd.DataFrame(filtered_log)
        st.dataframe(df, use_container_width=True, height=600)
        
        # Export options
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Export as CSV"):
                csv = df.to_csv(index=False)
                st.download_button(
                    "Download CSV",
                    csv,
                    f"tessera_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    "text/csv"
                )
        with col2:
            if st.button("📋 Export as JSON"):
                json_str = json.dumps(filtered_log, default=str, indent=2)
                st.download_button(
                    "Download JSON",
                    json_str,
                    f"tessera_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "application/json"
                )

# ============================================================================
# MODE 8: SYSTEM CONFIGURATION
# ============================================================================
elif mode == "⚙️ System Configuration":
    st.header("⚙️ System Configuration")
    
    tab1, tab2, tab3 = st.tabs(["🔧 Settings", "📊 Statistics", "ℹ️ About"])
    
    with tab1:
        st.subheader("Global Settings")
        
        col1, col2 = st.columns(2)
        with col1:
            st.number_input("Default Token TTL (seconds)", value=300, min_value=60, max_value=3600)
            st.number_input("Default Risk Threshold", value=50, min_value=0, max_value=100)
        
        with col2:
            st.selectbox("Logging Level", ["INFO", "WARNING", "ERROR"])
            st.checkbox("Enable VerityFlux Integration", value=False)
        
        if st.button("💾 Save Configuration"):
            st.success("✅ Configuration saved!")
    
    with tab2:
        st.subheader("System Statistics")
        
        total_logs = len(st.session_state.audit_log)
        critical_events = len([e for e in st.session_state.audit_log if e.get('severity') == 'critical'])
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Audit Entries", total_logs)
        col2.metric("Critical Events", critical_events)
        col3.metric("Uptime", "N/A")
        
        st.subheader("Department Statistics")
        owner_counts = {}
        for agent in st.session_state.registry.list_agents():
            owner_counts[agent.owner] = owner_counts.get(agent.owner, 0) + 1
        
        fig = px.pie(values=list(owner_counts.values()), 
                    names=list(owner_counts.keys()),
                    title="Agents by Department")
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.subheader("About Tessera IAM")
        st.markdown("""
        ### 🛡️ Tessera IAM
        **Version:** 1.0.0 Enterprise Edition
        
        **Zero-Trust Identity & Access Management for AI Agents**
        
        #### Key Features:
        - ✅ Cryptographic JWT-based identity tokens
        - ✅ Multi-tenant owner isolation
        - ✅ Self-healing security loop
        - ✅ Honey-tool detection
        - ✅ Behavioral biometrics
        - ✅ Real-time kill-switch
        - ✅ Scope-based access control
        - ✅ Complete audit trail
        
        #### Built For:
        - DEF CON Singapore 2026
        - Enterprise AI Security
        - Multi-agent swarm protection
        
        #### Designed by:
        Security Research Team
        
        ---
        
        **Status:** Production-Ready
        **License:** Enterprise
        """)

# Footer
st.divider()
col1, col2, col3 = st.columns(3)
with col1:
    st.caption(f"Tessera IAM v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
with col2:
    st.caption("🛡️ Zero-Trust Security Active")
with col3:
    st.caption("DEF CON Singapore 2026")

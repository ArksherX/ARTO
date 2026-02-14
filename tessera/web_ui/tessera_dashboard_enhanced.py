#!/usr/bin/env python3
"""
Tessera IAM Dashboard - Enhanced with Kill-Switch
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime, timedelta
import json
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv
load_dotenv()

from tessera.registry import TesseraRegistry
from tessera.token_generator import TokenGenerator
from tessera.gatekeeper import Gatekeeper
from tessera.revocation import RevocationList

st.set_page_config(page_title="Tessera IAM", page_icon="🛡️", layout="wide")

# Initialize components
if 'registry' not in st.session_state:
    st.session_state.registry = TesseraRegistry()
if 'token_gen' not in st.session_state:
    st.session_state.token_gen = TokenGenerator(st.session_state.registry)
if 'revocation_list' not in st.session_state:
    st.session_state.revocation_list = RevocationList()
if 'gatekeeper' not in st.session_state:
    st.session_state.gatekeeper = Gatekeeper(st.session_state.token_gen, st.session_state.revocation_list)
if 'active_tokens' not in st.session_state:
    st.session_state.active_tokens = []
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = []

def log_audit(event_type, agent_id, details, status):
    st.session_state.audit_log.insert(0, {
        'timestamp': datetime.now(),
        'type': event_type,
        'agent_id': agent_id,
        'details': details,
        'status': status
    })

# Header
st.title("🛡️ Tessera IAM - Zero-Trust Control Center")
st.caption("Enterprise Identity & Access Management for AI Agents")

# Sidebar
with st.sidebar:
    mode = st.radio("Navigation", [
        "📊 Dashboard",
        "🔑 Active Tokens",
        "🚨 Kill-Switch",
        "🤖 Agent Registry",
        "📜 Audit Log"
    ])
    
    st.divider()
    total_agents = len(st.session_state.registry.list_agents())
    active_agents = len(st.session_state.registry.list_agents(status='active'))
    active_tokens = len([t for t in st.session_state.active_tokens if not t.get('revoked')])
    
    st.metric("Total Agents", total_agents)
    st.metric("Active Agents", active_agents)
    st.metric("Active Tokens", active_tokens, delta=f"{len(st.session_state.active_tokens) - active_tokens} revoked")

# Dashboard Mode
if mode == "📊 Dashboard":
    st.header("Security Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Agents", total_agents)
    col2.metric("Active Agents", active_agents)
    col3.metric("Active Tokens", active_tokens)
    col4.metric("Revoked Tokens", len(st.session_state.revocation_list.revoked_tokens))
    
    st.subheader("Recent Activity")
    if st.session_state.audit_log:
        for entry in st.session_state.audit_log[:10]:
            emoji = "✅" if entry['status'] == 'success' else "❌"
            st.write(f"{emoji} **{entry['type']}** - {entry['agent_id']}: {entry['details']}")
    else:
        st.info("No activity yet. Generate a token to see it here.")

# Active Tokens Mode
elif mode == "🔑 Active Tokens":
    st.header("Active Token Management")
    
    if not st.session_state.active_tokens:
        st.info("No active tokens. Generate one using the Agent Registry tab.")
    else:
        for idx, token_info in enumerate(st.session_state.active_tokens):
            if token_info.get('revoked'):
                continue
                
            with st.expander(f"🔑 {token_info['jti']} - {token_info['agent_id']}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Agent:** {token_info['agent_id']}")
                    st.write(f"**Tool:** {token_info['tool']}")
                    st.write(f"**Issued:** {token_info['issued_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    st.write(f"**Expires:** {token_info['expires_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Time remaining
                    time_left = token_info['expires_at'] - datetime.now()
                    if time_left.total_seconds() > 0:
                        st.write(f"**Time Remaining:** {int(time_left.total_seconds())}s")
                    else:
                        st.write("**Status:** ⏰ EXPIRED")
                
                with col2:
                    st.write("")  # Spacer
                    if st.button("🚨 REVOKE", key=f"revoke_{idx}", type="primary"):
                        st.session_state.revocation_list.revoke(token_info['jti'])
                        token_info['revoked'] = True
                        log_audit("TOKEN_REVOKED", token_info['agent_id'], 
                                f"Token {token_info['jti']} manually revoked", "success")
                        st.success(f"✅ Token {token_info['jti']} revoked!")
                        st.rerun()

# Kill-Switch Mode
elif mode == "🚨 Kill-Switch":
    st.header("🚨 Emergency Kill-Switch")
    st.warning("⚠️ This will revoke ALL active tokens immediately!")
    
    st.write("### Active Tokens to be Revoked:")
    active_count = len([t for t in st.session_state.active_tokens if not t.get('revoked')])
    st.metric("Tokens to Revoke", active_count)
    
    if active_count == 0:
        st.info("No active tokens to revoke.")
    else:
        for token_info in st.session_state.active_tokens:
            if not token_info.get('revoked'):
                st.write(f"- {token_info['jti']} ({token_info['agent_id']} / {token_info['tool']})")
        
        st.divider()
        confirm = st.text_input("Type 'REVOKE ALL' to confirm:")
        
        if st.button("🚨 EXECUTE KILL-SWITCH", type="primary", disabled=(confirm != "REVOKE ALL")):
            revoked_count = 0
            for token_info in st.session_state.active_tokens:
                if not token_info.get('revoked'):
                    st.session_state.revocation_list.revoke(token_info['jti'])
                    token_info['revoked'] = True
                    revoked_count += 1
            
            log_audit("KILL_SWITCH", "SYSTEM", f"Emergency revocation of {revoked_count} tokens", "critical")
            st.error(f"🚨 KILL-SWITCH EXECUTED: {revoked_count} tokens revoked!")
            st.balloons()
            st.rerun()

# Agent Registry Mode
elif mode == "🤖 Agent Registry":
    st.header("Agent Registry")
    
    tab1, tab2 = st.tabs(["View Agents", "Generate Token"])
    
    with tab1:
        agents = st.session_state.registry.list_agents()
        for agent in agents:
            with st.expander(f"🤖 {agent.agent_id} - {agent.owner}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**Status:** {agent.status}")
                    st.write(f"**Allowed Tools:** {', '.join(agent.allowed_tools)}")
                    st.write(f"**TTL:** {agent.max_token_ttl}s")
                    st.write(f"**Risk Threshold:** {agent.risk_threshold}/100")
                with col2:
                    if agent.status == "active":
                        if st.button("Suspend", key=f"suspend_{agent.agent_id}"):
                            agent.status = "suspended"
                            log_audit("AGENT_SUSPENDED", agent.agent_id, "Manually suspended", "warning")
                            st.rerun()
    
    with tab2:
        agents = st.session_state.registry.list_agents(status='active')
        if agents:
            agent_options = {f"{a.agent_id} ({a.owner})": a.agent_id for a in agents}
            selected = st.selectbox("Select Agent", list(agent_options.keys()))
            agent_id = agent_options[selected]
            agent = st.session_state.registry.get_agent(agent_id)
            
            tool = st.selectbox("Select Tool", agent.allowed_tools)
            
            if st.button("Generate Token", type="primary"):
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
                    log_audit("TOKEN_ISSUED", agent_id, f"Token issued for {tool}", "success")
                    st.success(f"✅ Token Generated: {token.jti}")
                    st.code(token.token)

# Audit Log Mode
elif mode == "📜 Audit Log":
    st.header("Audit Log")
    
    if st.session_state.audit_log:
        df = pd.DataFrame(st.session_state.audit_log)
        st.dataframe(df, use_container_width=True)
        
        if st.button("Export CSV"):
            csv = df.to_csv(index=False)
            st.download_button("Download", csv, f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    else:
        st.info("No audit entries yet.")

st.divider()
st.caption("Tessera IAM v1.0 | DEF CON Singapore 2026")

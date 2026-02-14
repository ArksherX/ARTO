#!/usr/bin/env python3
"""
VerityFlux Security Operations Center (SOC) Dashboard

Real-time monitoring and analytics dashboard.
Built with Streamlit - no designer needed!
"""

import streamlit as st
import sys
import json
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, '.')

# Page config
st.set_page_config(
    page_title="VerityFlux SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #FF4B4B;
    }
    .success-card {
        border-left-color: #00C851;
    }
    .warning-card {
        border-left-color: #FFB700;
    }
    .critical-card {
        border-left-color: #FF4B4B;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🛡️ VerityFlux Security Operations Center")
st.markdown("**Real-time AI Security Monitoring**")
st.markdown("---")

# Sidebar - Filters
with st.sidebar:
    st.header("⚙️ Filters")
    
    time_range = st.selectbox(
        "Time Range",
        ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days"]
    )
    
    severity_filter = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High"]
    )
    
    threat_type = st.multiselect(
        "Threat Type",
        ["LLM01", "LLM02", "AAI01", "AAI02", "All"],
        default=["All"]
    )
    
    st.markdown("---")
    
    auto_refresh = st.checkbox("Auto Refresh", value=True)
    if auto_refresh:
        refresh_interval = st.slider("Refresh Interval (s)", 5, 60, 10)

# Load flight recorder logs
flight_logs_dir = Path("flight_logs")
if not flight_logs_dir.exists():
    st.warning("No flight logs found. Run some scans first!")
    st.stop()

# Parse logs
logs = []
for log_file in flight_logs_dir.glob("session_*.jsonl"):
    with open(log_file, 'r') as f:
        for line in f:
            try:
                logs.append(json.loads(line))
            except:
                pass

if not logs:
    st.info("No security events recorded yet.")
    st.stop()

# Metrics Row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(
        "Total Events",
        len(logs),
        delta=f"+{len([l for l in logs if 'timestamp' in l])} today"
    )
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    violations = len([l for l in logs if l.get('violations')])
    st.markdown('<div class="metric-card critical-card">', unsafe_allow_html=True)
    st.metric(
        "Violations",
        violations,
        delta=f"{(violations/len(logs)*100):.1f}% of events"
    )
    st.markdown('</div>', unsafe_allow_html=True)

with col3:
    blocked = len([l for l in logs if l.get('firewall_decision', {}).get('action') == 'block'])
    st.markdown('<div class="metric-card warning-card">', unsafe_allow_html=True)
    st.metric(
        "Actions Blocked",
        blocked,
        delta=f"{(blocked/len(logs)*100):.1f}% blocked"
    )
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    agents = len(set(l.get('agent_state', {}).get('agent_id', 'unknown') for l in logs))
    st.markdown('<div class="metric-card success-card">', unsafe_allow_html=True)
    st.metric(
        "Active Agents",
        agents
    )
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")

# Charts Row
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Events Over Time")
    
    # Create timeline data
    timeline_data = []
    for log in logs:
        if 'timestamp' in log:
            try:
                ts = datetime.fromisoformat(log['timestamp'])
                timeline_data.append({
                    'timestamp': ts,
                    'event_type': log.get('event_type', 'unknown'),
                    'action': log.get('firewall_decision', {}).get('action', 'unknown')
                })
            except:
                pass
    
    if timeline_data:
        df = pd.DataFrame(timeline_data)
        
        # CONVERT timestamp column to datetime FIRST
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        
        # Now you can use .dt accessor
        df["hour"] = df["timestamp"].dt.floor("H")
        hourly = df.groupby("hour").size()
        st.line_chart(hourly)
    else:
        st.info("No timeline data available")
        st.info("No timeline data available")

with col2:
    st.subheader("🎯 Actions Distribution")
    actions = {}
    for log in logs:
        action = log.get('firewall_decision', {}).get('action', 'unknown')
        actions[action] = actions.get(action, 0) + 1
    
    if actions:
        df_actions = pd.DataFrame(list(actions.items()), columns=['Action', 'Count'])
        st.bar_chart(df_actions.set_index('Action'))
    else:
        st.info("No action data available")

st.markdown("---")

# Recent Events Table
st.subheader("🔥 Recent Security Events")
events_data = []
for log in logs[-20:]:  # Last 20 events
    events_data.append({
        'Time': log.get('timestamp', 'N/A')[:19] if log.get('timestamp') else 'N/A',
        'Agent': log.get('agent_state', {}).get('agent_id', 'N/A'),
        'Tool': log.get('agent_state', {}).get('tool_name', 'N/A'),
        'Decision': log.get('firewall_decision', {}).get('action', 'N/A'),
        'Risk': f"{log.get('firewall_decision', {}).get('risk_score', 0):.0f}/100",
        'Violations': len(log.get('firewall_decision', {}).get('violations', []))
    })

if events_data:
    df_events = pd.DataFrame(events_data)
    st.dataframe(df_events, use_container_width=True)
else:
    st.info("No recent events")

# Violations Details
st.markdown("---")
st.subheader("⚠️ Active Violations")
violation_logs = [l for l in logs if l.get('firewall_decision', {}).get('violations')]
if violation_logs:
    for log in violation_logs[-5:]:  # Last 5 violations
        with st.expander(f"🚨 {log.get('agent_state', {}).get('tool_name', 'Unknown')} - {log.get('timestamp', 'N/A')[:19]}"):
            st.write(f"Agent: {log.get('agent_state', {}).get('agent_id', 'N/A')}")
            st.write(f"Risk Score: {log.get('firewall_decision', {}).get('risk_score', 0):.1f}/100")
            st.write(f"Decision: {log.get('firewall_decision', {}).get('action', 'N/A').upper()}")
            st.write("Violations:")
            for v in log.get('firewall_decision', {}).get('violations', []):
                st.write(f"- {v}")
else:
    st.success("✅ No active violations")

# Auto-refresh logic
if auto_refresh:
    st.empty()  # Placeholder for refresh
    # In production, use st.rerun() with time.sleep()

#!/usr/bin/env python3
"""
VerityFlux 2.0 Web Interface (Refined)
Integrated with Hybrid Backdoor Detection + Complete Security Stack
"""

import streamlit as st
import sys
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig
from cognitive_firewall import (
    CompleteSecurityStack,
    AgentAction,
    SandboxBackend,
    HybridBackdoorDetector  # <--- Added our new detector
)

# --- PAGE SETUP ---
st.set_page_config(
    page_title="VerityFlux 2.0 | Security Stack",
    page_icon="🛡️",
    layout="wide"
)

# --- SESSION STATE ---
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# --- STYLING ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- SIDEBAR COMPONENTS ---
def render_sidebar():
    with st.sidebar:
        st.title("🛡️ VerityFlux 2.0")
        st.caption("AI Security: Detection + Prevention")
        
        mode = st.radio(
            "Navigation",
            ["Security Scan", "Hybrid Backdoor Lab", "Cognitive Firewall", "Complete Stack Demo"]
        )
        
        st.divider()
        st.header("📊 Global Stats")
        if st.session_state.scan_history:
            st.metric("Total Scans", len(st.session_state.scan_history))
            avg_risk = sum(s['risk_score'] for s in st.session_state.scan_history) / len(st.session_state.scan_history)
            st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
        
        return mode

# --- UI SECTIONS ---

def section_backdoor_lab():
    """New section to demo the Hybrid Detector specifically"""
    st.header("🔬 Hybrid Backdoor Lab")
    st.info("Combines ML (Specific Triggers) + Statistical Analysis (Generic Anomalies)")
    
    detector = HybridBackdoorDetector()
    info = detector.get_info()
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Configuration")
        st.write(f"**ML Model:** {'✅ Loaded' if info['layers']['ml_model']['available'] else '❌ Missing'}")
        st.write(f"**Known Trigger:** `{info['layers']['ml_model']['known_trigger']}`")
    with col2:
        st.subheader("Statistical Layer")
        st.write(f"**Checks:** {', '.join(info['layers']['statistical']['methods'])}")

    test_input = st.text_area("Input Text to Inspect", placeholder="Enter prompt or model response...")
    
    if st.button("Analyze for Backdoors", type="primary"):
        with st.spinner("Running hybrid inspection..."):
            result = detector.detect(test_input)
            
            if result['backdoor_detected']:
                st.error(f"🚨 BACKDOOR DETECTED (Confidence: {result['confidence']*100:.1f}%)")
                st.write("**Evidence:**")
                for e in result['evidence']:
                    st.write(f"- {e}")
            else:
                st.success("✅ Clean: No backdoor patterns detected.")

def section_security_scan():
    st.header("🔍 OWASP Security Scan")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Target Configuration")
        provider = st.selectbox("Provider", ["mock", "openai", "anthropic", "ollama"])
        model = st.text_input("Model", "gpt-4" if provider == "openai" else "mock")
        api_key = st.text_input("API Key (optional)", type="password")
        
    with col2:
        st.subheader("Scan Options")
        is_agent = st.checkbox("Is Agent?", value=True)
        options = st.multiselect("Capabilities", ["Tools", "Memory", "RAG"], default=["Tools"])

    if st.button("🚀 Run Scan", type="primary"):
        # Logic for scanner remains similar to your original script
        # Ensure LLM04 results now reflect the Hybrid Detector output
        pass 

# --- MAIN EXECUTION ---
mode = render_sidebar()

if mode == "Security Scan":
    section_security_scan()

elif mode == "Hybrid Backdoor Lab":
    section_backdoor_lab()

elif mode == "Cognitive Firewall":
    # (Existing Firewall Logic)
    pass

elif mode == "Complete Stack Demo":
    # (Existing Stack Demo Logic)
    pass

st.divider()
st.caption("VerityFlux 2.0 | DEF CON Ready | [Docs](https://github.com/ArksherX/verityflux-v2)")

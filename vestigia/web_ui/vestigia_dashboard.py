#!/usr/bin/env python3
"""
Vestigia Dashboard - Immutable Observability UI (FIXED)
The "Truth Provider" visualization for CISOs

All timezone issues resolved

Save as: vestigia/web_ui/vestigia_dashboard.py
Run: streamlit run web_ui/vestigia_dashboard.py
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import from correct location
try:
    from core.ledger_engine import VestigiaLedger
    from security.verifier import ProductionVerifier
except ImportError:
    # Fallback to old location
    from vestigia_core import VestigiaLedger
    from verify_ledger import VestigiaVerifier as ProductionVerifier

# Page config
st.set_page_config(
    page_title="Vestigia - Immutable Observability",
    page_icon="🗃️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .status-success {
        color: #10b981;
        font-weight: bold;
    }
    .status-critical {
        color: #ef4444;
        font-weight: bold;
    }
    .status-blocked {
        color: #f59e0b;
        font-weight: bold;
    }
    .integrity-verified {
        background: #10b981;
        color: white;
        padding: 10px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .integrity-compromised {
        background: #ef4444;
        color: white;
        padding: 10px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'ledger' not in st.session_state:
    st.session_state.ledger = VestigiaLedger("data/vestigia_ledger.json")
if 'verifier' not in st.session_state:
    st.session_state.verifier = ProductionVerifier("data/vestigia_ledger.json")

# Header
st.title("🗃️ Vestigia - Immutable Observability")
st.caption("The Truth Provider for AI Agent Operations")

# Sidebar
with st.sidebar:
    st.header("Navigation")
    mode = st.radio(
        "Select View",
        ["📊 Dashboard", "📜 Audit Trail", "🔍 Verification", "➕ Log Event", "📤 Export"]
    )
    
    st.divider()
    
    # Quick stats
    try:
        events = st.session_state.ledger.query_events(limit=1000)
        total_events = len(events)
        
        critical_count = len([e for e in events if e.status == "CRITICAL"])
        blocked_count = len([e for e in events if e.status == "BLOCKED"])
        
        st.metric("Total Events", total_events)
        st.metric("Critical Events", critical_count)
        st.metric("Blocked Actions", blocked_count)
    except Exception as e:
        st.error(f"Error loading stats: {e}")
        total_events = 0
        critical_count = 0
        blocked_count = 0
        events = []
    
    st.divider()
    
    # Verification status
    try:
        result = st.session_state.verifier.verify_full()
        
        if result.is_valid:
            st.markdown('<div class="integrity-verified">✅ INTEGRITY VERIFIED</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="integrity-compromised">🚨 TAMPERING DETECTED</div>', unsafe_allow_html=True)
    except Exception as e:
        st.warning(f"Verification error: {e}")

# Main content
if mode == "📊 Dashboard":
    st.header("Security Dashboard")
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{total_events}</h3>
            <p>Total Events</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        success_count = len([e for e in events if e.status == "SUCCESS"])
        st.markdown(f"""
        <div class="metric-card">
            <h3>{success_count}</h3>
            <p>Successful</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{critical_count}</h3>
            <p>Critical</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{blocked_count}</h3>
            <p>Blocked</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # Event timeline - FIXED TIMEZONE ISSUE
    st.subheader("Event Timeline (Last 24 Hours)")
    
    if events:
        try:
            # Create dataframe with proper timezone handling
            df = pd.DataFrame([{
                'timestamp': e.timestamp,
                'actor_id': e.actor_id,
                'action_type': e.action_type,
                'status': e.status
            } for e in events[:100]])
            
            # Convert to datetime with UTC timezone
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
            
            # Create UTC-aware cutoff (FIXED)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            
            # Filter last 24h (now both are timezone-aware)
            df_recent = df[df['timestamp'] > cutoff]
            
            if not df_recent.empty:
                # Timeline chart
                fig = px.scatter(
                    df_recent,
                    x='timestamp',
                    y='action_type',
                    color='status',
                    hover_data=['actor_id'],
                    title="Event Activity Timeline"
                )
                
                fig.update_layout(
                    xaxis_title="Time (UTC)",
                    yaxis_title="Action Type",
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No events in last 24 hours")
        except Exception as e:
            st.error(f"Error rendering timeline: {e}")
    else:
        st.info("No events to display")
    
    # Recent critical events
    st.subheader("Recent Critical Events")
    
    critical_events = [e for e in events if e.status == "CRITICAL"][:5]
    
    if critical_events:
        for event in critical_events:
            # Handle evidence being dict or string
            evidence_text = event.evidence
            if isinstance(evidence_text, dict):
                evidence_text = evidence_text.get('summary', str(evidence_text))
            
            st.error(f"🚨 **{event.action_type}** - {event.actor_id}")
            st.caption(f"{event.timestamp} | {evidence_text}")
    else:
        st.success("No critical events detected")

elif mode == "📜 Audit Trail":
    st.header("Complete Audit Trail")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_actor = st.text_input("Filter by Actor ID", "")
    
    with col2:
        action_types = list(set([e.action_type for e in events])) if events else []
        filter_action = st.selectbox(
            "Filter by Action",
            ["All"] + action_types
        )
    
    with col3:
        filter_status = st.selectbox(
            "Filter by Status",
            ["All", "SUCCESS", "BLOCKED", "CRITICAL"]
        )
    
    # Apply filters
    filtered = events
    
    if filter_actor:
        filtered = [e for e in filtered if filter_actor in e.actor_id]
    
    if filter_action != "All":
        filtered = [e for e in filtered if e.action_type == filter_action]
    
    if filter_status != "All":
        filtered = [e for e in filtered if e.status == filter_status]
    
    st.write(f"Showing {len(filtered)} events")
    
    # Display as table
    if filtered:
        # Handle evidence being dict or string
        df_data = []
        for e in filtered:
            evidence_text = e.evidence
            if isinstance(evidence_text, dict):
                evidence_text = evidence_text.get('summary', str(evidence_text))
            
            df_data.append({
                'Timestamp': e.timestamp,
                'Event ID': e.event_id,
                'Actor': e.actor_id,
                'Action': e.action_type,
                'Status': e.status,
                'Evidence': evidence_text[:80] + '...' if len(str(evidence_text)) > 80 else evidence_text
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, height=600)
    else:
        st.info("No events match filters")

elif mode == "🔍 Verification":
    st.header("Ledger Verification")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Cryptographic Integrity")
        
        if st.button("🔍 Verify Now", type="primary"):
            with st.spinner("Verifying hash chain..."):
                result = st.session_state.verifier.verify_full()
            
            if result.is_valid:
                st.success(f"✅ VERIFICATION PASSED")
                st.write(f"All {result.total_entries} entries verified")
                st.write("No tampering detected")
            else:
                st.error(f"🚨 VERIFICATION FAILED")
                st.write(f"Tampering detected at index: {result.first_tampered_index}")
                st.write(f"Details: {result.tampering_details}")
        
        # Last verification
        try:
            result = st.session_state.verifier.verify_full()
            
            st.info(f"""
            **Last Verification:**
            - Status: {'✅ Valid' if result.is_valid else '🚨 Invalid'}
            - Entries Checked: {result.total_entries}
            - Time: {result.verification_timestamp}
            """)
        except Exception as e:
            st.error(f"Verification error: {e}")
    
    with col2:
        st.subheader("Time Gap Analysis")
        
        try:
            gaps = st.session_state.verifier.detect_time_gaps(max_gap_hours=2)
            
            if gaps:
                st.warning(f"⚠️ Found {len(gaps)} suspicious time gaps")
                
                for idx, desc in gaps[:10]:
                    st.write(f"- {desc}")
            else:
                st.success("✅ No suspicious time gaps detected")
        except Exception as e:
            st.error(f"Time gap analysis error: {e}")
    
    st.divider()
    
    # Full report
    st.subheader("Verification Report")
    
    if st.button("Generate Full Report"):
        try:
            report = st.session_state.verifier.generate_verification_report()
            
            st.json(report)
            
            # Download button
            report_json = json.dumps(report, indent=2)
            
            st.download_button(
                "📥 Download Report",
                report_json,
                f"vestigia_verification_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                "application/json"
            )
        except Exception as e:
            st.error(f"Report generation error: {e}")

elif mode == "➕ Log Event":
    st.header("Log New Event")
    
    st.info("💡 In production, events are logged automatically by Tessera/VerityFlux. This is for testing.")
    
    with st.form("log_event"):
        actor_id = st.text_input("Actor ID", "manual_test_agent")
        
        action_type = st.selectbox(
            "Action Type",
            [
                "IDENTITY_VERIFIED",
                "ACCESS_REQUEST",
                "TOOL_EXECUTION",
                "SECURITY_SCAN",
                "TOKEN_ISSUED",
                "TOKEN_REVOKED"
            ]
        )
        
        status = st.selectbox("Status", ["SUCCESS", "BLOCKED", "CRITICAL"])
        
        evidence = st.text_area("Evidence", "Manual test event")
        
        submitted = st.form_submit_button("Log Event")
        
        if submitted:
            try:
                event = st.session_state.ledger.append_event(
                    actor_id=actor_id,
                    action_type=action_type,
                    status=status,
                    evidence=evidence
                )
                
                st.success(f"✅ Event logged: {event.event_id}")
                st.json(event.to_dict())
            except Exception as e:
                st.error(f"Error logging event: {e}")

elif mode == "📤 Export":
    st.header("Export Compliance Report")
    
    st.write("Export the complete audit trail for compliance/legal purposes.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        export_format = st.radio("Format", ["JSON", "CSV"])
    
    with col2:
        include_hash = st.checkbox("Include Integrity Hashes", value=True)
    
    if st.button("Generate Export", type="primary"):
        try:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            
            if export_format == "JSON":
                output_path = f"vestigia_export_{timestamp}.json"
                path = st.session_state.ledger.export_compliance_report(
                    output_path,
                    format='json'
                )
            else:
                output_path = f"vestigia_export_{timestamp}.csv"
                path = st.session_state.ledger.export_compliance_report(
                    output_path,
                    format='csv'
                )
            
            st.success(f"✅ Export generated: {path}")
            
            # Read and offer download
            with open(path, 'r') as f:
                data = f.read()
            
            st.download_button(
                "📥 Download Export",
                data,
                output_path,
                "application/json" if export_format == "JSON" else "text/csv"
            )
        except Exception as e:
            st.error(f"Export error: {e}")
    
    st.divider()
    
    st.subheader("Compliance Information")
    
    st.info("""
    **Retention Policy:**
    - Financial Services: 7 years minimum
    - Healthcare (HIPAA): 6 years minimum
    - EU GDPR: Varies by data type
    
    **This ledger includes:**
    - Cryptographic proof of integrity (SHA-256 hash chain)
    - Complete audit trail of all operations
    - Tamper-evident design
    - Timestamp precision to milliseconds
    """)

# Footer
st.divider()
st.caption("Vestigia v1.0 | Immutable Observability | DEF CON Singapore 2026")

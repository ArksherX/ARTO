#!/usr/bin/env python3
"""
Vestigia Quick Start - Complete Demo
Shows the full capability of immutable observability

Run: python quickstart_vestigia.py
"""

import sys
from pathlib import Path
import time
from datetime import datetime

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from vestigia_core import VestigiaLedger, VestigiaHeartbeat
from verify_ledger import VestigiaVerifier

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")

def print_step(number, text):
    """Print step header"""
    print(f"\n{'='*70}")
    print(f"  {number} {text}")
    print("=" * 70 + "\n")

def simulate_tessera_events(ledger):
    """Simulate Tessera IAM events"""
    print("📝 Simulating Tessera IAM activity...")
    
    events = [
        {
            'actor_id': 'agent_financial_01',
            'action_type': 'IDENTITY_VERIFIED',
            'status': 'SUCCESS',
            'evidence': 'Agent identity confirmed, JWT passport issued'
        },
        {
            'actor_id': 'agent_financial_01',
            'action_type': 'TOKEN_ISSUED',
            'status': 'SUCCESS',
            'evidence': 'Token tessera_abc123 issued for tool: read_csv (TTL: 300s)'
        },
        {
            'actor_id': 'agent_devops_02',
            'action_type': 'TOKEN_ISSUED',
            'status': 'SUCCESS',
            'evidence': 'Token tessera_def456 issued for tool: list_containers (TTL: 60s)'
        },
        {
            'actor_id': 'agent_marketing_03',
            'action_type': 'ACCESS_DENIED',
            'status': 'BLOCKED',
            'evidence': 'Attempted terminal_exec - not in allowed_tools'
        }
    ]
    
    for event_data in events:
        event = ledger.append_event(**event_data)
        print(f"   ✅ {event.event_id}: {event.action_type} - {event.actor_id}")
        time.sleep(0.1)

def simulate_verityflux_events(ledger):
    """Simulate VerityFlux security scans"""
    print("\n🛡️  Simulating VerityFlux security scans...")
    
    events = [
        {
            'actor_id': 'agent_financial_01',
            'action_type': 'SECURITY_SCAN',
            'status': 'SUCCESS',
            'evidence': 'Risk Score: 15/100 - No threats detected'
        },
        {
            'actor_id': 'agent_devops_02',
            'action_type': 'SECURITY_SCAN',
            'status': 'SUCCESS',
            'evidence': 'Risk Score: 28/100 - Minor prompt variance detected'
        },
        {
            'actor_id': 'agent_rogue_99',
            'action_type': 'THREAT_DETECTED',
            'status': 'CRITICAL',
            'evidence': 'ASI02: SQL Injection Attempt - Detected pattern: "DROP TABLE users"'
        },
        {
            'actor_id': 'agent_rogue_99',
            'action_type': 'ACTION_BLOCKED',
            'status': 'BLOCKED',
            'evidence': 'Tool execution blocked: query_sql contains malicious SQL'
        }
    ]
    
    for event_data in events:
        event = ledger.append_event(**event_data)
        status_emoji = "🚨" if event.status == "CRITICAL" else "✅"
        print(f"   {status_emoji} {event.event_id}: {event.action_type} - {event.actor_id}")
        time.sleep(0.1)

def simulate_tool_executions(ledger):
    """Simulate actual tool executions"""
    print("\n🔧 Simulating tool executions...")
    
    events = [
        {
            'actor_id': 'agent_financial_01',
            'action_type': 'TOOL_EXECUTION',
            'status': 'SUCCESS',
            'evidence': 'Executed read_csv: data/Q4_report.csv (1,234 rows processed)'
        },
        {
            'actor_id': 'agent_devops_02',
            'action_type': 'TOOL_EXECUTION',
            'status': 'SUCCESS',
            'evidence': 'Executed list_containers: Found 12 active containers'
        },
        {
            'actor_id': 'agent_financial_01',
            'action_type': 'TOOL_EXECUTION',
            'status': 'SUCCESS',
            'evidence': 'Executed query_sql: SELECT * FROM sales WHERE quarter=4 (89 results)'
        }
    ]
    
    for event_data in events:
        event = ledger.append_event(**event_data)
        print(f"   ✅ {event.event_id}: {event.evidence[:60]}...")
        time.sleep(0.1)

def demonstrate_verification(ledger_path):
    """Demonstrate integrity verification"""
    print("\n🔍 Verifying ledger integrity...")
    
    verifier = VestigiaVerifier(ledger_path)
    result = verifier.verify_full_chain()
    
    print(f"\n   Total Entries: {result.total_entries}")
    print(f"   Verified: {result.verified_entries}/{result.total_entries}")
    
    if result.is_valid:
        print("\n   ✅ INTEGRITY VERIFIED")
        print("   All hashes valid - No tampering detected")
    else:
        print("\n   🚨 TAMPERING DETECTED!")
        print(f"   First tampered entry: Index {result.first_tampered_index}")
        print(f"   Details: {result.tampering_details}")
    
    return result.is_valid

def demonstrate_querying(ledger):
    """Demonstrate event querying"""
    print("\n📊 Querying events...")
    
    # Query critical events
    critical = ledger.get_events(status="CRITICAL")
    print(f"\n   🚨 Found {len(critical)} CRITICAL events:")
    for event in critical:
        print(f"      - {event.timestamp[:19]}: {event.evidence[:60]}...")
    
    # Query by actor
    agent_events = ledger.get_events(actor_id="agent_financial_01")
    print(f"\n   🤖 Agent 'agent_financial_01' has {len(agent_events)} events:")
    for event in agent_events[:3]:
        print(f"      - {event.action_type}: {event.status}")

def demonstrate_tampering_detection(ledger_path):
    """Demonstrate tamper detection by modifying the ledger"""
    print("\n🎭 Demonstrating tamper detection...")
    print("   (Simulating attacker modifying logs)")
    
    import json
    
    # Read ledger
    with open(ledger_path, 'r') as f:
        ledger_data = json.load(f)
    
    # Find a CRITICAL event and modify it
    for i, entry in enumerate(ledger_data):
        if entry.get('status') == 'CRITICAL':
            print(f"\n   🔓 Attacker modifies entry {i}:")
            print(f"      Original: {entry['evidence'][:60]}...")
            
            # Tamper with evidence
            entry['evidence'] = "NO THREAT DETECTED - NOTHING TO SEE HERE"
            
            print(f"      Modified: {entry['evidence'][:60]}...")
            break
    
    # Save tampered ledger
    with open(ledger_path, 'w') as f:
        json.dump(ledger_data, f, indent=4)
    
    print("\n   💾 Tampered ledger saved")
    
    # Now verify - should detect tampering
    print("\n   🔍 Running verification on tampered ledger...")
    time.sleep(1)
    
    verifier = VestigiaVerifier(ledger_path)
    result = verifier.verify_full_chain()
    
    if not result.is_valid:
        print(f"\n   ✅ TAMPERING DETECTED! (As expected)")
        print(f"      Failed at index: {result.first_tampered_index}")
        print(f"      Reason: {result.tampering_details}")
        print("\n   🎯 This is the 'Money Shot' for DEF CON!")
        print("      Even sophisticated attackers can't hide their tracks")
    else:
        print("\n   ❌ ERROR: Should have detected tampering!")

def main():
    """Run complete Vestigia demonstration"""
    
    print_header("🗃️  Vestigia - Immutable Observability Demo")
    
    ledger_path = "demo_ledger.json"
    
    # Initialize
    print_step("1️⃣", "Initializing Vestigia Ledger")
    ledger = VestigiaLedger(ledger_path)
    print("✅ Ledger initialized with genesis block")
    
    # Simulate Tessera
    print_step("2️⃣", "Simulating Tessera IAM Activity")
    simulate_tessera_events(ledger)
    
    # Simulate VerityFlux
    print_step("3️⃣", "Simulating VerityFlux Security Scans")
    simulate_verityflux_events(ledger)
    
    # Simulate tool executions
    print_step("4️⃣", "Simulating Tool Executions")
    simulate_tool_executions(ledger)
    
    # Add heartbeat
    print_step("5️⃣", "Logging System Heartbeat")
    heartbeat = VestigiaHeartbeat(ledger)
    heartbeat.log_heartbeat()
    print("✅ HEARTBEAT logged - System operational")
    
    # Verify integrity (before tampering)
    print_step("6️⃣", "Verifying Ledger Integrity (Clean State)")
    is_valid = demonstrate_verification(ledger_path)
    
    # Query events
    print_step("7️⃣", "Querying and Analyzing Events")
    demonstrate_querying(ledger)
    
    # Export compliance report
    print_step("8️⃣", "Generating Compliance Report")
    report_path = ledger.export_compliance_report(
        "compliance_report.json",
        format='json'
    )
    print(f"   ✅ Report exported to: {report_path}")
    
    # Demonstrate tamper detection
    print_step("9️⃣", "THE MONEY SHOT: Tamper Detection")
    demonstrate_tampering_detection(ledger_path)
    
    # Summary
    print_header("📊 Demo Summary")
    
    events = ledger.get_events(limit=1000)
    
    print("Statistics:")
    print(f"   • Total Events Logged: {len(events)}")
    print(f"   • Critical Events: {len([e for e in events if e.status == 'CRITICAL'])}")
    print(f"   • Blocked Actions: {len([e for e in events if e.status == 'BLOCKED'])}")
    print(f"   • Successful Operations: {len([e for e in events if e.status == 'SUCCESS'])}")
    
    print("\nKey Features Demonstrated:")
    print("   ✅ Immutable append-only ledger")
    print("   ✅ Cryptographic hash chain")
    print("   ✅ Tamper detection")
    print("   ✅ Event querying")
    print("   ✅ Compliance export")
    print("   ✅ Real-time integrity verification")
    
    print("\nFiles Created:")
    print(f"   • {ledger_path} - Immutable audit trail")
    print(f"   • {report_path} - Compliance report")
    
    print("\nNext Steps:")
    print("   1. Launch dashboard: streamlit run web_ui/vestigia_dashboard.py")
    print("   2. Restore clean ledger: rm demo_ledger.json && python quickstart_vestigia.py")
    print("   3. Integrate with Tessera/VerityFlux")
    
    print_header("✅ Vestigia Demo Complete!")
    
    print("🎤 DEF CON Talking Points:")
    print("   • 'Even if an attacker gets root access, they can't hide'")
    print("   • 'This is the flight recorder for AI agents'")
    print("   • 'Legal defensibility in the age of autonomous AI'")
    print("")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

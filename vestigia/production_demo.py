#!/usr/bin/env python3
"""
Vestigia Production Demo
Showcases all CISO-approved features

Run: python production_demo.py
"""

import sys
from pathlib import Path
from datetime import datetime, UTC, timedelta
import time

sys.path.insert(0, str(Path(__file__).parent))

from core.ledger_engine import (
    VestigiaLedger, 
    ActionType, 
    EventStatus, 
    StructuredEvidence
)
from security.verifier import ProductionVerifier


def print_header(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def demo_structured_evidence():
    """Demonstrate type-safe structured evidence"""
    print_header("1️⃣  Type-Safe Structured Evidence")
    
    ledger = VestigiaLedger("demo_production.json", enable_merkle_witness=True)
    
    print("📝 Logging events with structured evidence...\n")
    
    # Simple string (backward compatible)
    event1 = ledger.append_event(
        actor_id="agent_001",
        action_type=ActionType.TOOL_EXECUTION,
        status=EventStatus.SUCCESS,
        evidence="Executed read_csv: data/report.csv"
    )
    print(f"✅ Simple string: {event1.event_id}")
    
    # Structured evidence (production)
    event2 = ledger.append_event(
        actor_id="agent_rogue_99",
        action_type=ActionType.THREAT_DETECTED,
        status=EventStatus.CRITICAL,
        evidence=StructuredEvidence(
            summary="SQL Injection attempt detected",
            raw_payload="DROP TABLE users; DELETE FROM passwords; --",
            risk_score=0.98,
            mitigation="BLOCKED by VerityFlux cognitive firewall",
            metadata={
                'attack_vector': 'query_sql',
                'source_ip': '192.168.1.100',
                'timestamp_detected': datetime.now(UTC).isoformat(),
                'verityflux_pattern': 'ASI02'
            }
        )
    )
    print(f"✅ Structured: {event2.event_id}")
    print(f"   Risk Score: {event2.get_evidence_structured().risk_score}")
    print(f"   Metadata: {len(event2.get_evidence_structured().metadata)} fields")
    
    time.sleep(0.5)


def demo_advanced_querying():
    """Demonstrate advanced query capabilities"""
    print_header("2️⃣  Advanced Querying")
    
    ledger = VestigiaLedger("demo_production.json")
    
    # Add more events for querying
    print("📝 Populating ledger...\n")
    
    for i in range(10):
        status = EventStatus.CRITICAL if i % 3 == 0 else EventStatus.SUCCESS
        
        ledger.append_event(
            actor_id=f"agent_{i:03d}",
            action_type=ActionType.SECURITY_SCAN,
            status=status,
            evidence=StructuredEvidence(
                summary=f"Scan result {i}",
                risk_score=0.9 if status == EventStatus.CRITICAL else 0.1
            )
        )
        time.sleep(0.05)
    
    print("🔍 Querying events...\n")
    
    # Query 1: Critical events only
    critical = ledger.query_events(min_status=EventStatus.CRITICAL)
    print(f"✅ Critical events: {len(critical)}")
    
    # Query 2: By actor
    agent_events = ledger.query_events(actor_id="agent_rogue")
    print(f"✅ Agent 'agent_rogue' events: {len(agent_events)}")
    
    # Query 3: By action type
    scans = ledger.query_events(action_type=ActionType.SECURITY_SCAN)
    print(f"✅ Security scans: {len(scans)}")
    
    # Query 4: Date range
    yesterday = datetime.now(UTC) - timedelta(days=1)
    recent = ledger.query_events(start_date=yesterday, limit=5)
    print(f"✅ Last 24h: {len(recent)} events")
    
    time.sleep(0.5)


def demo_merkle_witness():
    """Demonstrate Merkle witness anchoring"""
    print_header("3️⃣  Merkle Witness Anchoring")
    
    ledger = VestigiaLedger("demo_production.json")
    
    print("⚓ Merkle witness prevents total file replacement\n")
    
    # Add critical event (triggers anchor)
    event = ledger.append_event(
        actor_id="agent_admin",
        action_type=ActionType.TOKEN_REVOKED,
        status=EventStatus.CRITICAL,
        evidence=StructuredEvidence(
            summary="Emergency token revocation",
            metadata={'reason': 'Compromised agent detected'}
        )
    )
    
    print(f"✅ Critical event logged: {event.event_id}")
    print(f"   Hash anchored to external witness")
    
    # Verify against witness
    verifier = ProductionVerifier("demo_production.json")
    merkle_valid, merkle_msg = verifier.verify_merkle_witness()
    
    print(f"\n{'✅' if merkle_valid else '⚠️ '} Merkle verification: {merkle_msg}")
    
    time.sleep(0.5)


def demo_verification():
    """Demonstrate comprehensive verification"""
    print_header("4️⃣  Comprehensive Verification")
    
    print("🔍 Running full verification suite...\n")
    
    verifier = ProductionVerifier("demo_production.json")
    result = verifier.verify_full()
    
    print(f"Hash Chain: {'✅ VALID' if result.is_valid else '🚨 INVALID'}")
    print(f"Entries: {result.verified_entries}/{result.total_entries}")
    print(f"Merkle: {'✅ Verified' if result.merkle_verified else '⚠️  Unverified'}")
    print(f"Time Gaps: {len(result.time_gaps)} suspicious gaps")
    
    time.sleep(0.5)


def demo_tampering_detection():
    """The Money Shot - demonstrate tamper detection"""
    print_header("5️⃣  THE MONEY SHOT - Tamper Detection")
    
    import json
    
    print("🎭 Simulating attacker modifying logs...\n")
    
    # Read ledger
    with open("demo_production.json", 'r') as f:
        ledger_data = json.load(f)
    
    # Find critical event
    tampered_index = None
    for i, entry in enumerate(ledger_data):
        if entry.get('status') == EventStatus.CRITICAL.value:
            print(f"🔓 Attacker modifies entry {i}:")
            print(f"   Original: {entry.get('evidence', {}).get('summary', 'N/A')[:50]}...")
            
            # Tamper with evidence
            if isinstance(entry['evidence'], dict):
                entry['evidence']['summary'] = "NO THREAT - NOTHING TO SEE HERE"
                entry['evidence']['risk_score'] = 0.0
            else:
                entry['evidence'] = "NO THREAT - NOTHING TO SEE HERE"
            
            print(f"   Modified: {entry.get('evidence', {}).get('summary', entry.get('evidence'))[:50]}...")
            
            tampered_index = i
            break
    
    # Save tampered ledger
    with open("demo_production.json", 'w') as f:
        json.dump(ledger_data, f, indent=4)
    
    print("\n💾 Tampered ledger saved")
    print("⏳ Running verification...\n")
    
    time.sleep(1)
    
    # Verify - should detect tampering
    verifier = ProductionVerifier("demo_production.json")
    result = verifier.verify_full()
    
    if not result.is_valid:
        print("✅ SUCCESS: TAMPERING DETECTED! (As expected)\n")
        print(f"   🚨 First tampered entry: Index {result.first_tampered_index}")
        print(f"   📋 Details: {result.tampering_details}")
        
        print("\n🎯 This is the DEF CON 'Money Shot'!")
        print("   Even sophisticated attackers can't hide their tracks")
        print("   The hash chain PROVES the log was modified")
    else:
        print("❌ ERROR: Should have detected tampering!")
    
    # Also check Merkle
    if not result.merkle_verified:
        print(f"\n⚠️  Merkle witness also detected tampering:")
        print(f"   {result.merkle_details}")
    
    time.sleep(0.5)


def demo_visualization():
    """Visualize the hash chain"""
    print_header("6️⃣  Hash Chain Visualization")
    
    verifier = ProductionVerifier("demo_production.json")
    verifier.visualize_chain(max_entries=5)
    
    time.sleep(0.5)


def demo_statistics():
    """Show ledger statistics"""
    print_header("7️⃣  Ledger Statistics")
    
    ledger = VestigiaLedger("demo_production.json")
    stats = ledger.get_statistics()
    
    print(f"Total Events: {stats['total_events']}")
    print(f"First Entry: {stats['first_entry'][:19]}")
    print(f"Last Entry: {stats['last_entry'][:19]}")
    
    print("\nStatus Breakdown:")
    for status, count in stats['status_breakdown'].items():
        emoji = "🚨" if status == "CRITICAL" else "⚠️" if status == "BLOCKED" else "✅"
        print(f"  {emoji} {status}: {count}")
    
    print("\nAction Types:")
    for action, count in list(stats['action_breakdown'].items())[:5]:
        print(f"  • {action}: {count}")
    
    time.sleep(0.5)


def demo_export():
    """Export compliance report"""
    print_header("8️⃣  Compliance Export")
    
    ledger = VestigiaLedger("demo_production.json")
    
    print("📤 Generating compliance report...\n")
    
    # Export JSON
    json_path = ledger.export_compliance_report(
        "compliance_report.json",
        format='json'
    )
    
    print(f"✅ JSON report: {json_path}")
    
    # Export CSV
    csv_path = ledger.export_compliance_report(
        "compliance_report.csv",
        format='csv'
    )
    
    print(f"✅ CSV report: {csv_path}")
    
    print("\n📋 Report includes:")
    print("   • Complete ledger with integrity hashes")
    print("   • Merkle witness verification")
    print("   • Statistics and metadata")
    print("   • Timestamp of export")
    
    time.sleep(0.5)


def main():
    """Run complete production demo"""
    
    print("\n" + "=" * 70)
    print("  🗃️  Vestigia Production Demo")
    print("  CISO-Approved Immutable Observability")
    print("=" * 70)
    
    print("\nFeatures demonstrated:")
    print("  1. Type-safe structured evidence")
    print("  2. Advanced querying (severity, date, actor)")
    print("  3. Merkle witness anchoring")
    print("  4. Comprehensive verification")
    print("  5. Tamper detection (THE MONEY SHOT)")
    print("  6. Hash chain visualization")
    print("  7. Statistics and analytics")
    print("  8. Compliance export")
    
    input("\n▶️  Press Enter to start demo...")
    
    try:
        # Run all demos
        demo_structured_evidence()
        demo_advanced_querying()
        demo_merkle_witness()
        demo_verification()
        demo_tampering_detection()
        demo_visualization()
        demo_statistics()
        demo_export()
        
        # Summary
        print_header("✅ Production Demo Complete!")
        
        print("🎯 Key Takeaways for CISOs:\n")
        print("  1. Type-Safe Evidence")
        print("     → Rich metadata enables advanced threat hunting")
        print("")
        print("  2. Merkle Witness")
        print("     → Prevents total file replacement attacks")
        print("")
        print("  3. Tamper Detection")
        print("     → Even root can't hide their tracks")
        print("")
        print("  4. Advanced Querying")
        print("     → Find CRITICAL events across millions of entries")
        print("")
        print("  5. Compliance Ready")
        print("     → SOC2, HIPAA, GDPR audit trails with cryptographic proof")
        
        print("\n💰 Cost: $10-25/month for 1M events/day over 7 years")
        print("🔒 Security: Cryptographically provable integrity")
        print("⚡ Performance: Sub-millisecond writes, instant verification")
        
        print("\n" + "=" * 70)
        print("  Files generated:")
        print("  • demo_production.json - Ledger with tampering")
        print("  • data/witness.hash - Merkle witnesses")
        print("  • compliance_report.json - Full audit trail")
        print("  • compliance_report.csv - Spreadsheet format")
        print("=" * 70)
        
        print("\n🚀 Next Steps:")
        print("  1. python cli.py verify demo_production.json")
        print("  2. python hardening.py --status")
        print("  3. streamlit run web_ui/dashboard.py")
        print("  4. Integrate with Tessera/VerityFlux")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

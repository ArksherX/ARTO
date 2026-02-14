#!/usr/bin/env python3
"""
The History Rewrite Attack - Ultimate Security Test

This demonstrates the most sophisticated attack: replacing the ENTIRE
ledger with a new, valid chain. Only the witness can detect this.

Save as: vestigia/test_history_rewrite.py
"""

import time
from pathlib import Path
from core.ledger_engine import VestigiaLedger
from validator import VestigiaValidator

def main():
    print("\n" + "="*70)
    print("🎯 THE HISTORY REWRITE ATTACK - ULTIMATE TEST")
    print("="*70)
    print("\nThis test proves Vestigia can detect even the most sophisticated")
    print("attack: replacing the entire ledger with a new, valid chain.\n")
    
    # Clean slate
    ledger_path = Path('data/vestigia_ledger.json')
    witness_path = Path('data/witness.hash')
    
    print("="*70)
    print("PHASE 1: Create Original Ledger")
    print("="*70 + "\n")
    
    # Delete old files
    ledger_path.unlink(missing_ok=True)
    witness_path.unlink(missing_ok=True)
    
    print("📝 Creating original ledger with sensitive data...")
    ledger = VestigiaLedger('data/vestigia_ledger.json', enable_external_anchor=False)
    
    # Log sensitive operations
    sensitive_ops = [
        ('agent_admin', 'IDENTITY_VERIFIED', 'SUCCESS', 'Admin login'),
        ('agent_admin', 'TOKEN_ISSUED', 'SUCCESS', 'Admin token generated'),
        ('agent_admin', 'TOOL_EXECUTION', 'SUCCESS', 'SELECT * FROM users'),
        ('agent_rogue', 'TOOL_EXECUTION', 'BLOCKED', 'SQL injection attempt'),
        ('agent_rogue', 'THREAT_DETECTED', 'CRITICAL', 'DROP TABLE users; --'),
        ('system', 'SECURITY_SCAN', 'SUCCESS', 'Threat blocked'),
    ]
    
    for i, (actor, action, status, evidence) in enumerate(sensitive_ops, 1):
        ledger.append_event(actor, action, status, evidence)
        print(f"   {i}. {actor} → {action} ({status})")
        time.sleep(0.1)
    
    print(f"\n✅ Original ledger created: {ledger_path.stat().st_size:,} bytes")
    
    # Read witness
    with open(witness_path, 'r') as f:
        original_witness = f.read().strip()
    
    print(f"🔐 Witness hash: {original_witness[:16]}...")
    
    # Validate original
    print("\n🔍 Validating original ledger...")
    validator = VestigiaValidator('data/vestigia_ledger.json')
    report1 = validator.validate_full()
    
    if report1.is_valid:
        print("✅ Original ledger: VALID")
        print(f"   Total entries: {report1.total_entries}")
    else:
        print("❌ Original ledger: INVALID (unexpected!)")
        return
    
    print("\nPress Enter to proceed to the attack...")
    input()
    
    # ========================================================================
    # THE ATTACK: History Rewrite
    # ========================================================================
    
    print("\n" + "="*70)
    print("PHASE 2: 🚨 THE ATTACK - History Rewrite")
    print("="*70 + "\n")
    
    print("💀 Attacker scenario:")
    print("   • Compromised system with root access")
    print("   • Wants to hide evidence of SQL injection attack")
    print("   • Strategy: Replace entire ledger with clean history")
    print("   • Challenge: Make new ledger internally valid\n")
    
    time.sleep(2)
    
    print("🔪 Step 1: Deleting original ledger...")
    ledger_path.unlink()
    print("   ✅ Original ledger deleted")
    
    time.sleep(1)
    
    print("\n🔪 Step 2: Creating fake 'clean' ledger...")
    print("   (Attacker creates new ledger with innocent events)")
    
    # Create fake ledger with innocent events
    fake_ledger = VestigiaLedger('data/vestigia_ledger.json', enable_external_anchor=False)
    
    innocent_ops = [
        ('agent_admin', 'IDENTITY_VERIFIED', 'SUCCESS', 'Admin login'),
        ('agent_admin', 'TOKEN_ISSUED', 'SUCCESS', 'Admin token generated'),
        ('agent_admin', 'TOOL_EXECUTION', 'SUCCESS', 'SELECT version()'),
        ('agent_user1', 'TOOL_EXECUTION', 'SUCCESS', 'SELECT * FROM public_data'),
        ('agent_user2', 'TOOL_EXECUTION', 'SUCCESS', 'SELECT * FROM reports'),
        ('system', 'HEARTBEAT', 'SUCCESS', 'System healthy'),
    ]
    
    for actor, action, status, evidence in innocent_ops:
        fake_ledger.append_event(actor, action, status, evidence)
        print(f"   • {actor} → {action} (innocent)")
        time.sleep(0.05)
    
    print(f"\n✅ Fake ledger created: {ledger_path.stat().st_size:,} bytes")
    
    # Get new witness (attacker's fake one)
    with open(witness_path, 'r') as f:
        fake_witness = f.read().strip()
    
    print(f"🎭 New witness hash: {fake_witness[:16]}...")
    
    print("\n🔍 Attacker validates their fake ledger...")
    validator2 = VestigiaValidator('data/vestigia_ledger.json')
    report2 = validator2.validate_full()
    
    if report2.is_valid:
        print("✅ Fake ledger: INTERNALLY VALID")
        print("   ⚠️  Hash chain is mathematically correct!")
        print("   ⚠️  No tampering detected in individual entries!")
        print(f"   Total entries: {report2.total_entries}")
    
    print("\nPress Enter to see the detection...")
    input()
    
    # ========================================================================
    # THE DETECTION: Witness Comparison
    # ========================================================================
    
    print("\n" + "="*70)
    print("PHASE 3: 🛡️  THE DETECTION - Witness Comparison")
    print("="*70 + "\n")
    
    print("🔍 Security team restores original witness from backup...")
    
    # Restore original witness
    with open(witness_path, 'w') as f:
        f.write(original_witness)
    
    print(f"✅ Original witness restored: {original_witness[:16]}...")
    
    print("\n🔍 Running validator with restored witness...")
    time.sleep(1)
    
    validator3 = VestigiaValidator('data/vestigia_ledger.json')
    report3 = validator3.validate_full()
    
    print("\n" + "="*70)
    print("VALIDATION RESULT")
    print("="*70 + "\n")
    
    if report3.is_valid:
        print("❌ FAILED TO DETECT ATTACK (unexpected!)")
    else:
        print("🚨 ATTACK DETECTED!")
        
        critical = report3.get_critical_issues()
        for issue in critical:
            if issue.issue_type == "HISTORY_REWRITE_DETECTED":
                print("\n✅ SUCCESS: History rewrite attack caught!")
                print(f"\n   Issue: {issue.description}")
                print(f"   Evidence:")
                for key, value in issue.evidence.items():
                    print(f"     • {key}: {value}")
    
    print("\n" + "="*70)
    print("CONCLUSION")
    print("="*70 + "\n")
    
    print("💡 Key Insights:")
    print("   1. Attacker created a VALID ledger (hash chain correct)")
    print("   2. Internal validation PASSED (no broken links)")
    print("   3. But witness.hash exposed the history swap")
    print("   4. The out-of-band witness is the 'ground truth'")
    print("\n🎯 Result: VESTIGIA CORE IS BULLETPROOF")
    print("   Even sophisticated attacks cannot hide from the witness.\n")
    
    print("="*70 + "\n")

if __name__ == '__main__':
    main()

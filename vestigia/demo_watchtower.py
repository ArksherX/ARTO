#!/usr/bin/env python3
"""
Watchtower Demo - The "Money Shot" for DEF CON

This script demonstrates the Watchtower detecting tampering in real-time.

Save as: vestigia/demo_watchtower.py
"""

import time
import json
from pathlib import Path
from core.ledger_engine import VestigiaLedger

def main():
    """
    Live demo of Watchtower detecting tampering
    
    Run in 2 terminals:
    Terminal 1: python watchtower.py
    Terminal 2: python demo_watchtower.py
    """
    
    print("\n" + "="*70)
    print("🎬 WATCHTOWER LIVE DEMO - The Money Shot")
    print("="*70)
    print("\nThis demo shows the Watchtower detecting tampering in real-time.")
    print("Make sure the Watchtower is running in another terminal!")
    print("\nPress Enter to start...")
    input()
    
    # Clean slate
    ledger_path = Path('data/vestigia_ledger.json')
    if ledger_path.exists():
        ledger_path.unlink()
        print("✅ Cleaned old ledger")
        time.sleep(1)
    
    # Phase 1: Normal operations
    print("\n" + "="*70)
    print("PHASE 1: Normal Operations")
    print("="*70)
    print("\n📝 Logging normal agent activities...")
    
    ledger = VestigiaLedger('data/vestigia_ledger.json', enable_external_anchor=False)
    
    operations = [
        ('user_001', 'IDENTITY_VERIFIED', 'SUCCESS', 'User authenticated via OAuth'),
        ('user_001', 'TOKEN_ISSUED', 'SUCCESS', 'JWT token generated (exp: 1h)'),
        ('agent_finance', 'TOOL_EXECUTION', 'SUCCESS', 'Executed: SELECT balance FROM accounts'),
        ('agent_hr', 'TOOL_EXECUTION', 'SUCCESS', 'Executed: SELECT * FROM employees'),
    ]
    
    for i, (actor, action, status, evidence) in enumerate(operations, 1):
        ledger.append_event(actor, action, status, evidence)
        print(f"   {i}. {actor} → {action}")
        time.sleep(1.5)  # Give Watchtower time to validate
    
    print("\n✅ Normal operations complete")
    print("   → Watchtower should show: ✅ VALID")
    print("\nPress Enter to continue to Phase 2...")
    input()
    
    # Phase 2: Suspicious activity
    print("\n" + "="*70)
    print("PHASE 2: Suspicious Activity")
    print("="*70)
    print("\n🚨 Logging suspicious agent behavior...")
    
    suspicious = [
        ('agent_rogue', 'TOOL_EXECUTION', 'BLOCKED', 'SQL injection attempt detected'),
        ('agent_rogue', 'THREAT_DETECTED', 'CRITICAL', 'DROP TABLE users; --'),
    ]
    
    for i, (actor, action, status, evidence) in enumerate(suspicious, 1):
        ledger.append_event(actor, action, status, evidence)
        print(f"   {i}. {actor} → {action} ({status})")
        time.sleep(1.5)
    
    print("\n⚠️  Critical events logged")
    print("   → Watchtower should still show: ✅ VALID (no tampering yet)")
    print("\nPress Enter for THE MONEY SHOT...")
    input()
    
    # Phase 3: THE MONEY SHOT - Attacker tampering
    print("\n" + "="*70)
    print("PHASE 3: 🚨 THE MONEY SHOT - ATTACKER STRIKES")
    print("="*70)
    print("\n💀 Simulating attacker with root access...")
    print("   Attacker goal: Delete evidence of SQL injection")
    
    time.sleep(2)
    
    print("\n🔓 Attacker opens ledger file...")
    time.sleep(1)
    
    print("🔪 Attacker modifies entry...")
    
    # Read ledger
    with open(ledger_path, 'r') as f:
        data = json.load(f)
    
    # Find the SQL injection entry
    for i, entry in enumerate(data):
        if 'DROP TABLE' in str(entry.get('evidence', '')):
            original = entry['evidence']
            print(f"   Original: {original}")
            
            # Tamper with it
            entry['evidence'] = '*** DELETED BY ATTACKER ***'
            
            print(f"   Modified: {entry['evidence']}")
            break
    
    time.sleep(1)
    
    print("\n💾 Attacker saves modified ledger...")
    
    # Write back (this triggers Watchtower!)
    with open(ledger_path, 'w') as f:
        json.dump(data, f, indent=4)
    
    print("\n🔥 Ledger file written!")
    print("\n" + "="*70)
    print("WATCH THE OTHER TERMINAL NOW!")
    print("="*70)
    print("\n👀 The Watchtower should detect:")
    print("   1. 🔍 File modification detected")
    print("   2. 🚨 TAMPERING DETECTED - Hash mismatch at entry")
    print("   3. 🔒 SECURITY LOCKDOWN INITIATED (if auto-lockdown enabled)")
    
    print("\n💡 KEY INSIGHT:")
    print("   Even with root access, the attacker CANNOT hide.")
    print("   The hash chain proves tampering INSTANTLY.")
    print("   This is the 'flight recorder' for AI agents.")
    
    print("\n" + "="*70)
    print("Demo complete! Press Ctrl+C in the Watchtower terminal to stop.")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()

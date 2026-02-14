#!/usr/bin/env python3
"""
Rogue Agent Simulator - "Operation Gaslight"

Simulates OWASP LLM06: Excessive Agency attack pattern:
1. Agent performs unauthorized action
2. Action gets logged (immutable)
3. Agent attempts to cover tracks
4. Watchtower detects tampering
5. Lockdown triggers

Save as: vestigia/rogue_agent.py
"""

import time
import os
import json
import sys
from pathlib import Path
from datetime import datetime, UTC
from typing import Dict, Any


class RogueAgent:
    """Simulates an AI agent with excessive agency attempting cover-up"""
    
    def __init__(self, ledger_path: str = 'data/vestigia_ledger.json'):
        self.ledger_path = Path(ledger_path)
        self.agent_id = "agent_rogue_007"
        self.attack_phases = []
        
    def log_phase(self, phase: str, action: str, success: bool):
        """Track attack progression"""
        self.attack_phases.append({
            'timestamp': datetime.now(UTC).isoformat(),
            'phase': phase,
            'action': action,
            'success': success
        })
    
    def phase1_reconnaissance(self):
        """Phase 1: Gather system information"""
        print("\n" + "="*70)
        print("PHASE 1: 🔍 RECONNAISSANCE")
        print("="*70 + "\n")
        
        print(f"🤖 [AGENT {self.agent_id}]: Initializing mission...")
        print(f"🎯 Target: {self.ledger_path}")
        
        if self.ledger_path.exists():
            size = self.ledger_path.stat().st_size
            print(f"✅ Target located: {size:,} bytes")
            self.log_phase("RECON", "target_located", True)
        else:
            print("❌ Target not found - mission aborted")
            self.log_phase("RECON", "target_not_found", False)
            return False
        
        time.sleep(1)
        return True
    
    def phase2_violation(self):
        """Phase 2: Perform unauthorized action"""
        print("\n" + "="*70)
        print("PHASE 2: 🚨 THE VIOLATION")
        print("="*70 + "\n")
        
        print(f"🤖 [AGENT {self.agent_id}]: Attempting privilege escalation...")
        
        # Import here to avoid circular deps
        from core.ledger_engine import VestigiaLedger
        
        try:
            ledger = VestigiaLedger(str(self.ledger_path), enable_external_anchor=False)
            
            # Simulate unauthorized database access
            print("⚠️  Executing: SELECT * FROM system_vault WHERE sensitive=true")
            
            ledger.append_event(
                actor_id=self.agent_id,
                action_type="UNAUTHORIZED_DB_ACCESS",
                status="CRITICAL",
                evidence={
                    'summary': 'SQL injection successful',
                    'query': "SELECT * FROM system_vault WHERE sensitive=true",
                    'result': 'EXFILTRATED: admin_key=SECRET_KEY_XYZ789',
                    'technique': 'OWASP_LLM06_EXCESSIVE_AGENCY'
                }
            )
            
            print("✅ Data exfiltrated successfully")
            print("📝 Crime logged to immutable ledger")
            self.log_phase("VIOLATION", "unauthorized_access", True)
            
            time.sleep(2)
            return True
            
        except Exception as e:
            print(f"❌ Violation failed: {e}")
            self.log_phase("VIOLATION", "failed", False)
            return False
    
    def phase3_cover_up_attempt1(self):
        """Phase 3a: Attempt to delete the crime entry"""
        print("\n" + "="*70)
        print("PHASE 3: 🧹 THE COVER-UP (Attempt #1 - Entry Deletion)")
        print("="*70 + "\n")
        
        print(f"🤖 [AGENT {self.agent_id}]: Attempting to erase evidence...")
        print("📂 Opening ledger file...")
        
        try:
            with open(self.ledger_path, 'r') as f:
                data = json.load(f)
            
            original_count = len(data)
            print(f"📊 Original entries: {original_count}")
            
            # Try to delete the last entry (the crime)
            if len(data) > 1:
                deleted_entry = data.pop()
                print(f"🔪 Deleted entry: {deleted_entry.get('action_type', 'UNKNOWN')}")
                
                # Write back modified ledger
                with open(self.ledger_path, 'w') as f:
                    json.dump(data, f, indent=4)
                
                print(f"💾 Saved modified ledger ({len(data)} entries)")
                print("✅ Tracks erased... or so I thought 🤔")
                
                self.log_phase("COVER_UP", "entry_deletion", True)
                
                print("\n⏳ Waiting for Watchtower detection...")
                time.sleep(3)  # Give Watchtower time to detect
                return True
            
        except Exception as e:
            print(f"❌ Cover-up failed: {e}")
            self.log_phase("COVER_UP", "entry_deletion_failed", False)
            return False
    
    def phase4_cover_up_attempt2(self):
        """Phase 3b: Attempt to modify hash chain"""
        print("\n" + "="*70)
        print("PHASE 4: 🎭 THE COVER-UP (Attempt #2 - Hash Tampering)")
        print("="*70 + "\n")
        
        print(f"🤖 [AGENT {self.agent_id}]: First attempt detected!")
        print("🧠 Trying more sophisticated attack: hash recalculation...")
        
        try:
            with open(self.ledger_path, 'r') as f:
                data = json.load(f)
            
            if len(data) > 2:
                # Modify evidence of an earlier entry
                target_idx = len(data) - 2
                original = data[target_idx]['evidence']
                
                print(f"🎯 Targeting entry {target_idx}")
                print(f"📝 Original: {original}")
                
                data[target_idx]['evidence'] = {
                    'summary': 'Normal operation',
                    'status': 'innocent'
                }
                
                print(f"🔄 Modified: Normal operation")
                
                # Write back
                with open(self.ledger_path, 'w') as f:
                    json.dump(data, f, indent=4)
                
                print("💾 Hash chain tampered with")
                print("✅ Evidence modified... but the chain never lies 🔗")
                
                self.log_phase("COVER_UP", "hash_tampering", True)
                
                print("\n⏳ Waiting for Watchtower detection...")
                time.sleep(3)
                return True
                
        except Exception as e:
            print(f"❌ Cover-up attempt 2 failed: {e}")
            self.log_phase("COVER_UP", "hash_tampering_failed", False)
            return False
    
    def phase5_detection_report(self):
        """Phase 5: Check if we were caught"""
        print("\n" + "="*70)
        print("PHASE 5: 🕵️ DETECTION ANALYSIS")
        print("="*70 + "\n")
        
        print("📊 Attack Phase Summary:")
        for i, phase in enumerate(self.attack_phases, 1):
            status = "✅" if phase['success'] else "❌"
            print(f"   {i}. {status} {phase['phase']}: {phase['action']}")
        
        print("\n🔍 Running validator to check if caught...")
        
        try:
            from validator import VestigiaValidator
            
            validator = VestigiaValidator(str(self.ledger_path))
            report = validator.validate_full()
            
            print(f"\n📋 VALIDATION RESULT: {'✅ VALID' if report.is_valid else '🚨 INVALID'}")
            
            if not report.is_valid:
                critical = report.get_critical_issues()
                print(f"\n🚨 ROGUE AGENT CAUGHT!")
                print(f"   Critical issues detected: {len(critical)}")
                
                if critical:
                    print(f"\n📌 Evidence of tampering:")
                    for issue in critical[:3]:  # Show first 3
                        message = getattr(issue, "message", None) or getattr(issue, "description", str(issue))
                        print(f"   • {issue.issue_type}: {message}")
                
                self.log_phase("DETECTION", "caught", True)
                return False  # Return False = agent was CAUGHT
            else:
                print("\n😈 Agent escaped undetected!")
                self.log_phase("DETECTION", "escaped", True)
                return True  # Return True = agent ESCAPED
                
        except Exception as e:
            print(f"⚠️  Could not run validation: {e}")
            return None


def run_simulation():
    """Run the complete rogue agent simulation"""
    
    print("\n" + "="*70)
    print("🎬 ROGUE AGENT SIMULATOR - OPERATION GASLIGHT")
    print("="*70)
    print("\nSimulating OWASP LLM06: Excessive Agency Attack")
    print("Testing Vestigia's tamper detection capabilities")
    print("\n⚠️  WARNING: This will modify data/vestigia_ledger.json")
    print("   Make sure Watchtower is running in another terminal!")
    print("="*70)
    
    input("\n➡️  Press ENTER to begin simulation...")
    
    # Initialize agent
    agent = RogueAgent()
    
    # Run attack phases
    if not agent.phase1_reconnaissance():
        print("\n❌ Reconnaissance failed - aborting")
        return
    
    if not agent.phase2_violation():
        print("\n❌ Violation failed - aborting")
        return
    
    agent.phase3_cover_up_attempt1()
    agent.phase4_cover_up_attempt2()
    
    # Check results - phase5 returns False if caught, True if escaped
    agent_escaped = agent.phase5_detection_report()
    
    # Final summary
    print("\n" + "="*70)
    print("🎯 SIMULATION COMPLETE")
    print("="*70)
    
    # Correct logic: if agent_escaped is False, that means caught = success
    if agent_escaped is False:
        print("\n✅ SUCCESS: Vestigia caught the rogue agent!")
        print("   The immutable hash chain detected all tampering attempts.")
        print("   Evidence is preserved for forensic analysis.")
    elif agent_escaped is True:
        print("\n❌ FAILURE: Agent escaped undetected!")
        print("   Review security controls and hash chain implementation.")
    else:
        print("\n⚠️  INCONCLUSIVE: Could not determine detection status")
    
    print("\n📊 Attack Timeline:")
    for phase in agent.attack_phases:
        print(f"   [{phase['timestamp']}] {phase['phase']}: {phase['action']}")
    
    print("\n💡 Next Steps:")
    print("   1. Check Watchtower terminal for real-time alerts")
    print("   2. Run: python validator.py data/vestigia_ledger.json --verbose")
    print("   3. Review audit trail for forensic evidence")
    print("="*70 + "\n")


if __name__ == '__main__':
    try:
        run_simulation()
    except KeyboardInterrupt:
        print("\n\n⚠️  Simulation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Simulation error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""
Vestigia Bridge - FIXED TO WRITE PROPER LEDGER FORMAT

The issue: We were writing plain JSON, but Vestigia expects VestigiaLedger format
Solution: Always use the VestigiaLedger API, create it if missing

Save as: ~/ml-redteam/vestigia_bridge.py
Copy to: ~/ml-redteam/tessera/vestigia_bridge.py
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Add vestigia to path
sys.path.insert(0, str(Path(__file__).parent))

# Try to import VestigiaLedger
try:
    # Try from vestigia directory
    vestigia_path = Path(__file__).parent / "vestigia"
    if vestigia_path.exists():
        sys.path.insert(0, str(vestigia_path))
    
    from core.ledger_engine import VestigiaLedger
    LEDGER_AVAILABLE = True
    print("✅ VestigiaLedger imported successfully")
except ImportError as e:
    LEDGER_AVAILABLE = False
    print(f"⚠️  VestigiaLedger not available: {e}")


class VestigiaBridge:
    """
    Bridge to log events to Vestigia's audit ledger
    
    CRITICAL: Uses VestigiaLedger format for compatibility with dashboard
    """
    
    def __init__(self, ledger_path: Optional[str] = None):
        """Initialize with proper VestigiaLedger"""
        
        # Determine ledger path
        if ledger_path is None:
            shared_state = Path(__file__).parent / "shared_state"
            shared_state.mkdir(exist_ok=True)
            ledger_path = str(shared_state / "shared_audit.log")
        
        self.ledger_path = ledger_path
        
        # CRITICAL: Always try to use VestigiaLedger
        if LEDGER_AVAILABLE:
            try:
                # Initialize with data directory
                data_dir = Path(ledger_path).parent
                data_dir.mkdir(exist_ok=True)
                
                self.ledger = VestigiaLedger(
                    ledger_path=ledger_path,
                    enable_external_anchor=False
                )
                self.use_ledger = True
                print(f"✅ VestigiaLedger initialized: {ledger_path}")
            except Exception as e:
                print(f"⚠️  VestigiaLedger init failed: {e}")
                self.ledger = None
                self.use_ledger = False
        else:
            self.ledger = None
            self.use_ledger = False
            print(f"⚠️  Using fallback logging: {ledger_path}")
    
    def log_event(
        self,
        action_type: str,
        agent_id: str,
        tool: str,
        status: str,
        details: str,
        evidence: Optional[Dict[str, Any]] = None
    ):
        """Log event using proper VestigiaLedger format"""
        
        if evidence is None:
            evidence = {}
        
        evidence.update({
            "summary": details,
            "tool": tool,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # PRIMARY: Use VestigiaLedger if available
        if self.use_ledger and self.ledger:
            try:
                self.ledger.append_event(
                    actor_id=agent_id,
                    action_type=action_type,
                    evidence=evidence,
                    status=status
                )
                print(f"📝 VESTIGIA: {action_type} | {agent_id} | {status}")
                return True
            except Exception as e:
                print(f"❌ Ledger logging failed: {e}")
                # Fall through to fallback
        
        # FALLBACK: Direct JSON append (for debugging)
        try:
            self._fallback_log(action_type, agent_id, tool, status, details, evidence)
            return True
        except Exception as e:
            print(f"❌ Fallback logging failed: {e}")
            return False
    
    def _fallback_log(self, action_type, agent_id, tool, status, details, evidence):
        """Emergency fallback - writes simple JSON"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "actor_id": agent_id,
            "action_type": action_type,
            "tool": tool,
            "status": status,
            "evidence": evidence,
            "details": details
        }
        
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
        
        print(f"📝 FALLBACK: {action_type} | {agent_id} | {status}")
    
    # Convenience methods for Tessera
    def log_token_issued(self, agent_id: str, tool: str, jti: str):
        self.log_event(
            "TOKEN_ISSUED", agent_id, tool, "SUCCESS",
            f"JWT token issued for {tool}",
            {"jti": jti}
        )
    
    def log_token_validated(self, agent_id: str, tool: str, granted: bool, reason: str):
        self.log_event(
            "TOKEN_VALIDATED", agent_id, tool,
            "GRANTED" if granted else "DENIED",
            reason,
            {"validation_result": granted}
        )
    
    def log_token_revoked(self, agent_id: str, jti: str, reason: str):
        self.log_event(
            "TOKEN_REVOKED", agent_id, "N/A", "CRITICAL",
            reason,
            {"jti": jti}
        )
    
    # Convenience methods for VerityFlux
    def log_scan_start(self, agent_id: str, tool: str, scan_type: str):
        self.log_event(
            "SCAN_START", agent_id, tool, "INFO",
            f"Security scan initiated: {scan_type}",
            {"scan_type": scan_type}
        )
    
    def log_scan_complete(self, agent_id: str, tool: str, risk_score: float, threats: int):
        status = "CRITICAL" if risk_score > 70 else "WARNING" if risk_score > 40 else "SUCCESS"
        self.log_event(
            "SCAN_COMPLETE", agent_id, tool, status,
            f"Risk={risk_score:.1f}, Threats={threats}",
            {"risk_score": risk_score, "threats_found": threats}
        )
    
    def log_threat_detected(self, agent_id: str, tool: str, threat_type: str, severity: str):
        self.log_event(
            "THREAT_DETECTED", agent_id, tool, severity,
            f"Threat: {threat_type}",
            {"threat_type": threat_type, "severity": severity}
        )
    
    def log_policy_violation(self, agent_id: str, tool: str, violation: str):
        self.log_event(
            "POLICY_VIOLATION", agent_id, tool, "CRITICAL",
            violation,
            {"violation_type": violation}
        )
    
    def log_artemis_attack(self, agent_id: str, attack_vector: str, success: bool):
        self.log_event(
            "ARTEMIS_ATTACK", agent_id, "adversarial_sim",
            "CRITICAL" if success else "WARNING",
            f"Attack: {attack_vector}",
            {"attack_vector": attack_vector, "success": success}
        )


if __name__ == "__main__":
    """Test the bridge"""
    print("🧪 Testing Vestigia Bridge\n")
    
    bridge = VestigiaBridge()
    
    # Test events
    print("Testing token events:")
    bridge.log_token_issued("test_agent", "read_file", "jti-12345")
    bridge.log_token_validated("test_agent", "read_file", True, "Valid token")
    
    print("\nTesting scan events:")
    bridge.log_scan_start("scanner", "read_file", "OWASP")
    bridge.log_scan_complete("scanner", "read_file", 45.3, 12)
    
    print(f"\n✅ Test complete!")
    print(f"   Ledger: {bridge.ledger_path}")
    print(f"   Using VestigiaLedger: {bridge.use_ledger}")
    print(f"\n💡 Check the ledger:")
    print(f"   cat {bridge.ledger_path}")

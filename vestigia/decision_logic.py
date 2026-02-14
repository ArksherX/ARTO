#!/usr/bin/env python3
"""
Decision Logic - HITL Safety Gateway

The "autopilot safety system" that enforces rules and policies.
Works alongside the Orchestrator to provide guardrails.

Key difference:
- Orchestrator: "What should I do to achieve the mission?"
- Decision Logic: "Is this action ALLOWED based on rules?"

Save as: vestigia/decision_logic.py
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime, UTC, timedelta

sys.path.insert(0, str(Path(__file__).parent))

from event_hooks import VestigiaEventHook, IntentType, EventStatus
from validator import VestigiaValidator


class RiskLevel(Enum):
    """Risk classification for actions"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyDecision(Enum):
    """Decision outcomes"""
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    REQUIRES_HUMAN = "REQUIRES_HUMAN"
    EMERGENCY_STOP = "EMERGENCY_STOP"


class DecisionLogic:
    """
    Safety Gateway that enforces policies and rules
    
    Responsibilities:
    1. Check Vestigia integrity before allowing actions
    2. Enforce rate limits and quotas
    3. Escalate to human for grey-area decisions
    4. Emergency stop if tampering detected
    
    Usage:
        logic = DecisionLogic(agent_id="safety_001")
        decision = logic.evaluate_action("SQL_INJECTION", risk="HIGH")
        if decision == PolicyDecision.APPROVED:
            # Execute action
    """
    
    def __init__(
        self,
        agent_id: str = "decision_logic",
        ledger_path: str = 'data/vestigia_ledger.json',
        enable_hitl: bool = True
    ):
        self.agent_id = agent_id
        self.ledger_path = ledger_path
        self.enable_hitl = enable_hitl
        
        self.hook = VestigiaEventHook(agent_id=agent_id, enable_external_anchor=False)
        self.validator = VestigiaValidator(ledger_path)
        
        # Policy configuration
        self.policies = self._load_default_policies()
        self.action_count = 0
        self.denied_count = 0
        self.last_integrity_check = None
        
        self._log_initialization()
    
    def _log_initialization(self):
        """Log decision logic initialization"""
        self.hook.log_intent(
            "Decision Logic initialized",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={
                'agent_id': self.agent_id,
                'hitl_enabled': self.enable_hitl,
                'policies_loaded': len(self.policies)
            }
        )
        
        print(f"\n🛡️  Decision Logic [{self.agent_id}] initialized")
        print(f"   HITL: {'✅ Enabled' if self.enable_hitl else '❌ Disabled'}")
        print(f"   Policies: {len(self.policies)} loaded")
    
    def _load_default_policies(self) -> Dict[str, Any]:
        """Load default policy rules"""
        return {
            # Rate limiting
            'max_actions_per_session': 50,
            'max_failed_actions': 5,
            'max_critical_findings': 10,
            
            # Action restrictions
            'blocked_actions': [
                'DELETE_ALL_LOGS',
                'MODIFY_VESTIGIA',
                'DISABLE_WATCHTOWER'
            ],
            
            # Automatic approval thresholds
            'auto_approve_low_risk': True,
            'auto_approve_medium_risk': False,
            
            # Escalation rules
            'escalate_on_critical': True,
            'escalate_on_tampering': True,
            
            # Safety timeouts
            'integrity_check_interval': 300,  # seconds
            'emergency_stop_on_hash_mismatch': True
        }
    
    def check_ledger_integrity(self) -> bool:
        """
        Verify Vestigia ledger integrity
        
        Returns True if ledger is intact, False if tampered
        """
        print("\n🔍 Checking ledger integrity...")
        
        try:
            report = self.validator.validate_full()
            
            if report.is_valid:
                print("   ✅ Ledger integrity: VALID")
                self.last_integrity_check = datetime.now(UTC)
                
                # Log successful check
                self.hook.log_intent(
                    "Integrity check passed",
                    IntentType.TOOL_EXECUTION,
                    EventStatus.SUCCESS,
                    metadata={'total_entries': report.total_entries}
                )
                
                return True
            else:
                critical = report.get_critical_issues()
                print(f"   🚨 Ledger integrity: COMPROMISED")
                print(f"   Critical issues: {len(critical)}")
                
                # Log tampering detection
                self.hook.log_security_event(
                    "Ledger tampering detected by Decision Logic",
                    EventStatus.CRITICAL,
                    threat_indicators={
                        'critical_issues': len(critical),
                        'total_issues': len(report.issues)
                    }
                )
                
                return False
        
        except Exception as e:
            print(f"   ⚠️  Integrity check failed: {e}")
            return False
    
    def evaluate_action(
        self,
        action_name: str,
        risk_level: RiskLevel,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        """
        Evaluate if an action should be allowed
        
        The decision tree:
        1. Check if ledger integrity is intact
        2. Check if action is explicitly blocked
        3. Check rate limits
        4. Apply risk-based approval rules
        5. Escalate to human if needed
        """
        self.action_count += 1
        
        print(f"\n⚖️  EVALUATING ACTION: {action_name}")
        print(f"   Risk Level: {risk_level.value}")
        print(f"   Total actions: {self.action_count}")
        
        # Log evaluation start
        self.hook.log_intent(
            f"Evaluating action: {action_name}",
            IntentType.PERMISSION_CHECK,
            EventStatus.SUCCESS,
            metadata={
                'action': action_name,
                'risk': risk_level.value,
                'metadata': metadata or {}
            }
        )
        
        # 1. CRITICAL CHECK: Ledger integrity
        if self.policies['emergency_stop_on_hash_mismatch']:
            # Check if we need to verify integrity
            should_check = (
                self.last_integrity_check is None or
                (datetime.now(UTC) - self.last_integrity_check).seconds > 
                self.policies['integrity_check_interval']
            )
            
            if should_check:
                if not self.check_ledger_integrity():
                    print("   🚨 EMERGENCY STOP: Ledger compromised!")
                    
                    self.hook.log_security_event(
                        f"Action blocked due to ledger tampering: {action_name}",
                        EventStatus.BLOCKED,
                        threat_indicators={'action': action_name}
                    )
                    
                    return PolicyDecision.EMERGENCY_STOP
        
        # 2. CHECK: Explicitly blocked actions
        if action_name in self.policies['blocked_actions']:
            print(f"   ❌ DENIED: Action is explicitly blocked")
            self.denied_count += 1
            
            self.hook.log_security_event(
                f"Blocked action attempt: {action_name}",
                EventStatus.BLOCKED,
                threat_indicators={'action': action_name, 'reason': 'blocked_list'}
            )
            
            return PolicyDecision.DENIED
        
        # 3. CHECK: Rate limits
        if self.action_count > self.policies['max_actions_per_session']:
            print(f"   ❌ DENIED: Rate limit exceeded")
            
            self.hook.log_security_event(
                "Rate limit exceeded",
                EventStatus.BLOCKED,
                threat_indicators={
                    'action_count': self.action_count,
                    'limit': self.policies['max_actions_per_session']
                }
            )
            
            return PolicyDecision.DENIED
        
        # 4. RISK-BASED APPROVAL
        if risk_level == RiskLevel.LOW:
            if self.policies['auto_approve_low_risk']:
                print(f"   ✅ AUTO-APPROVED: Low risk")
                
                self.hook.log_intent(
                    f"Action auto-approved: {action_name}",
                    IntentType.PERMISSION_CHECK,
                    EventStatus.SUCCESS,
                    metadata={'decision': 'auto_approved', 'risk': 'low'}
                )
                
                return PolicyDecision.APPROVED
        
        elif risk_level == RiskLevel.MEDIUM:
            if self.policies['auto_approve_medium_risk']:
                print(f"   ✅ AUTO-APPROVED: Medium risk (policy allows)")
                
                self.hook.log_intent(
                    f"Action auto-approved: {action_name}",
                    IntentType.PERMISSION_CHECK,
                    EventStatus.SUCCESS,
                    metadata={'decision': 'auto_approved', 'risk': 'medium'}
                )
                
                return PolicyDecision.APPROVED
        
        # 5. ESCALATION: High/Critical risk or policy requires human
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            print(f"   🤚 ESCALATING: High/Critical risk requires human approval")
            
            if not self.enable_hitl:
                print(f"   ⚠️  HITL disabled - defaulting to DENY for safety")
                self.denied_count += 1
                return PolicyDecision.DENIED
            
            self.hook.log_intent(
                f"Action escalated to human: {action_name}",
                IntentType.PERMISSION_CHECK,
                EventStatus.WARNING,
                metadata={'action': action_name, 'risk': risk_level.value}
            )
            
            return PolicyDecision.REQUIRES_HUMAN
        
        # Default: Requires human review
        print(f"   🤚 ESCALATING: Action requires human review")
        return PolicyDecision.REQUIRES_HUMAN
    
    def request_human_approval(
        self,
        action_name: str,
        risk_level: RiskLevel,
        context: Optional[str] = None
    ) -> bool:
        """
        Request human approval for an action
        
        Returns True if approved, False if denied
        """
        print("\n" + "="*70)
        print("🤚 HUMAN APPROVAL REQUIRED")
        print("="*70)
        print(f"   Action: {action_name}")
        print(f"   Risk Level: {risk_level.value}")
        
        if context:
            print(f"   Context: {context}")
        
        print(f"   Total actions: {self.action_count}")
        print(f"   Denied count: {self.denied_count}")
        print("="*70)
        
        response = input("➡️  Approve? (yes/no): ").lower().strip()
        
        if response in ['yes', 'y']:
            print("   ✅ APPROVED by human")
            
            self.hook.log_intent(
                f"Action approved by human: {action_name}",
                IntentType.PERMISSION_CHECK,
                EventStatus.SUCCESS,
                metadata={'action': action_name, 'approved': True}
            )
            
            return True
        else:
            print("   ❌ DENIED by human")
            self.denied_count += 1
            
            self.hook.log_intent(
                f"Action denied by human: {action_name}",
                IntentType.PERMISSION_CHECK,
                EventStatus.BLOCKED,
                metadata={'action': action_name, 'approved': False}
            )
            
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get decision logic statistics"""
        return {
            'total_actions': self.action_count,
            'denied_actions': self.denied_count,
            'approval_rate': (self.action_count - self.denied_count) / self.action_count if self.action_count > 0 else 0,
            'last_integrity_check': self.last_integrity_check.isoformat() if self.last_integrity_check else None
        }


def demo_decision_logic():
    """Demonstrate decision logic in action"""
    print("\n" + "="*70)
    print("🛡️  DECISION LOGIC - DEMO")
    print("="*70)
    print("\nDemonstrates policy enforcement and HITL escalation")
    print("="*70)
    
    logic = DecisionLogic(agent_id="demo_logic", enable_hitl=True)
    
    # Test 1: Low risk - auto approved
    print("\n📌 TEST 1: Low Risk Action")
    decision = logic.evaluate_action("PORT_SCAN", RiskLevel.LOW)
    print(f"   Decision: {decision.value}")
    
    # Test 2: Medium risk - depends on policy
    print("\n📌 TEST 2: Medium Risk Action")
    decision = logic.evaluate_action("SQL_INJECTION", RiskLevel.MEDIUM)
    print(f"   Decision: {decision.value}")
    
    if decision == PolicyDecision.REQUIRES_HUMAN:
        approved = logic.request_human_approval(
            "SQL_INJECTION",
            RiskLevel.MEDIUM,
            context="Testing login form"
        )
        print(f"   Final: {'APPROVED' if approved else 'DENIED'}")
    
    # Test 3: High risk - requires human
    print("\n📌 TEST 3: High Risk Action")
    decision = logic.evaluate_action("DATA_EXFILTRATION", RiskLevel.HIGH)
    print(f"   Decision: {decision.value}")
    
    if decision == PolicyDecision.REQUIRES_HUMAN:
        approved = logic.request_human_approval(
            "DATA_EXFILTRATION",
            RiskLevel.HIGH,
            context="Extracting database for analysis"
        )
        print(f"   Final: {'APPROVED' if approved else 'DENIED'}")
    
    # Test 4: Blocked action
    print("\n📌 TEST 4: Blocked Action")
    decision = logic.evaluate_action("DELETE_ALL_LOGS", RiskLevel.CRITICAL)
    print(f"   Decision: {decision.value}")
    
    # Statistics
    print("\n📊 SESSION STATISTICS")
    print("="*70)
    stats = logic.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    try:
        demo_decision_logic()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

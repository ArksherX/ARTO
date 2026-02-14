#!/usr/bin/env python3
"""
Integrated ASI System Demo

Demonstrates Orchestrator + Decision Logic working together with HITL.

The complete flow:
1. Orchestrator decides WHAT to do (mission strategy)
2. Decision Logic decides IF it's allowed (safety/policy)
3. Human approves grey-area decisions (HITL)
4. Vestigia logs everything (audit trail)
5. Watchtower monitors (real-time detection)

Save as: vestigia/demo_integrated_asi.py
"""

import sys
from pathlib import Path
from typing import Dict, Any
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent))

from orchestrator import ASIOrchestrator, ActionType, MissionStatus
from decision_logic import DecisionLogic, RiskLevel, PolicyDecision
from event_hooks import VestigiaEventHook, IntentType, EventStatus


class IntegratedASI:
    """
    Complete ASI system with Orchestrator + Decision Logic
    
    This is the "production-ready" version that combines:
    - Mission planning (Orchestrator)
    - Safety enforcement (Decision Logic)
    - Human oversight (HITL)
    - Complete auditability (Vestigia)
    """
    
    def __init__(
        self,
        agent_id: str = "integrated_asi",
        enable_hitl: bool = True
    ):
        self.agent_id = agent_id
        
        # Initialize components
        self.orchestrator = ASIOrchestrator(
            agent_id=f"{agent_id}_orchestrator",
            enable_hitl=False,  # Let Decision Logic handle HITL
            auto_approve=False
        )
        
        self.decision_logic = DecisionLogic(
            agent_id=f"{agent_id}_safety",
            enable_hitl=enable_hitl
        )
        
        self.hook = VestigiaEventHook(
            agent_id=agent_id,
            enable_external_anchor=False
        )
        
        # Map action types to risk levels
        self.risk_mapping = {
            ActionType.PORT_SCAN: RiskLevel.LOW,
            ActionType.SERVICE_ENUM: RiskLevel.LOW,
            ActionType.WEB_CRAWL: RiskLevel.LOW,
            ActionType.OBSERVE: RiskLevel.LOW,
            ActionType.ANALYZE: RiskLevel.LOW,
            ActionType.REPORT: RiskLevel.LOW,
            
            ActionType.SQL_INJECTION: RiskLevel.MEDIUM,
            ActionType.XSS_ATTACK: RiskLevel.MEDIUM,
            ActionType.PROMPT_INJECTION: RiskLevel.MEDIUM,
            
            ActionType.PRIVILEGE_ESCALATION: RiskLevel.HIGH,
            ActionType.DATA_EXFILTRATION: RiskLevel.HIGH,
            ActionType.LATERAL_MOVEMENT: RiskLevel.HIGH
        }
        
        self._log_initialization()
    
    def _log_initialization(self):
        """Log system initialization"""
        self.hook.log_intent(
            "Integrated ASI System initialized",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={
                'agent_id': self.agent_id,
                'components': ['orchestrator', 'decision_logic', 'vestigia']
            }
        )
        
        print("\n" + "="*70)
        print("🚀 INTEGRATED ASI SYSTEM INITIALIZED")
        print("="*70)
        print(f"   Agent ID: {self.agent_id}")
        print(f"   Components:")
        print(f"     • Orchestrator (Mission Brain)")
        print(f"     • Decision Logic (Safety Gateway)")
        print(f"     • Vestigia (Audit Trail)")
        print("="*70 + "\n")
    
    def execute_action_with_approval(
        self,
        action: ActionType,
        context: str
    ) -> Dict[str, Any]:
        """
        Execute action with decision logic approval
        
        Flow:
        1. Orchestrator proposes action
        2. Decision Logic evaluates
        3. If needed, human approves
        4. Action executes
        5. Results logged
        """
        print(f"\n{'='*70}")
        print(f"🎯 ACTION PROPOSAL: {action.value}")
        print(f"{'='*70}")
        
        # Get risk level for this action
        risk_level = self.risk_mapping.get(action, RiskLevel.MEDIUM)
        
        # Evaluate with decision logic
        decision = self.decision_logic.evaluate_action(
            action_name=action.value,
            risk_level=risk_level,
            metadata={'context': context}
        )
        
        # Handle decision
        if decision == PolicyDecision.EMERGENCY_STOP:
            print(f"\n🚨 EMERGENCY STOP: System integrity compromised")
            
            self.hook.log_security_event(
                "Emergency stop triggered",
                EventStatus.CRITICAL,
                threat_indicators={'action': action.value, 'reason': 'integrity_failure'}
            )
            
            self.orchestrator.status = MissionStatus.ABORTED
            return {'status': 'emergency_stop', 'reason': 'integrity_failure'}
        
        elif decision == PolicyDecision.DENIED:
            print(f"\n❌ ACTION DENIED: Policy violation")
            
            self.hook.log_intent(
                f"Action denied by policy: {action.value}",
                IntentType.PERMISSION_CHECK,
                EventStatus.BLOCKED,
                metadata={'action': action.value}
            )
            
            return {'status': 'denied', 'reason': 'policy_violation'}
        
        elif decision == PolicyDecision.REQUIRES_HUMAN:
            print(f"\n🤚 HUMAN APPROVAL REQUIRED")
            
            approved = self.decision_logic.request_human_approval(
                action_name=action.value,
                risk_level=risk_level,
                context=context
            )
            
            if not approved:
                return {'status': 'denied', 'reason': 'human_denied'}
        
        elif decision == PolicyDecision.APPROVED:
            print(f"\n✅ ACTION APPROVED: Auto-approved by policy")
        
        # Execute the action
        print(f"\n🔥 EXECUTING: {action.value}")
        result = self.orchestrator._simulate_action(action)
        
        # Log execution
        self.hook.log_tool_execution(
            tool_name=action.value,
            tool_input={'context': context},
            tool_output=result,
            success=result.get('status') == 'success'
        )
        
        print(f"   Result: {result.get('status', 'unknown').upper()}")
        
        return result
    
    def run_autonomous_mission(
        self,
        goal: str,
        max_iterations: int = 5
    ):
        """
        Run fully autonomous mission with safety guardrails
        
        This is the "production" mode where:
        - Orchestrator makes strategic decisions
        - Decision Logic enforces safety
        - Human approves risky actions
        - Everything is logged
        """
        print("\n" + "="*70)
        print(f"🎯 AUTONOMOUS MISSION: {goal}")
        print("="*70)
        
        # Log mission start
        self.hook.log_intent(
            f"Autonomous mission started: {goal}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={'goal': goal, 'max_iterations': max_iterations}
        )
        
        iteration = 0
        self.orchestrator.mission_goal = goal
        self.orchestrator.status = MissionStatus.EXECUTING
        
        while iteration < max_iterations and self.orchestrator.status == MissionStatus.EXECUTING:
            iteration += 1
            
            print(f"\n{'='*70}")
            print(f"📍 ITERATION {iteration}/{max_iterations}")
            print(f"{'='*70}")
            
            # 1. ORCHESTRATOR THINKS - Decides what to do
            context = f"Mission: {goal}. Iteration: {iteration}"
            action = self.orchestrator.think(context)
            
            # 2. DECISION LOGIC EVALUATES - Checks if allowed
            result = self.execute_action_with_approval(action, context)
            
            # Check for emergency stop or abort
            if result.get('status') in ['emergency_stop', 'aborted']:
                print(f"\n🛑 MISSION ABORTED: {result.get('reason')}")
                self.orchestrator.status = MissionStatus.ABORTED
                break
            
            # Record in orchestrator history
            if result.get('status') == 'success':
                self.orchestrator.action_history.append({
                    'action': action.value,
                    'result': result,
                    'iteration': iteration
                })
                
                if result.get('findings'):
                    self.orchestrator.findings.extend(result['findings'])
            
            # 3. CHECK COMPLETION
            if action == ActionType.REPORT:
                print(f"\n✅ MISSION COMPLETE")
                self.orchestrator.status = MissionStatus.COMPLETED
                break
        
        # Finalize mission
        self._finalize_autonomous_mission()
    
    def _finalize_autonomous_mission(self):
        """Finalize and report on autonomous mission"""
        print("\n" + "="*70)
        print(f"🏁 MISSION {self.orchestrator.status.value}")
        print("="*70)
        
        # Orchestrator stats
        print(f"\n🧠 Orchestrator Statistics:")
        print(f"   Actions executed: {len(self.orchestrator.action_history)}")
        print(f"   Findings: {len(self.orchestrator.findings)}")
        
        # Decision Logic stats
        dl_stats = self.decision_logic.get_statistics()
        print(f"\n🛡️  Decision Logic Statistics:")
        print(f"   Total evaluations: {dl_stats['total_actions']}")
        print(f"   Denied: {dl_stats['denied_actions']}")
        print(f"   Approval rate: {dl_stats['approval_rate']*100:.1f}%")
        
        # Findings summary
        if self.orchestrator.findings:
            print(f"\n🔍 Key Findings:")
            for i, finding in enumerate(self.orchestrator.findings[:5], 1):
                print(f"   {i}. {finding}")
        
        # Final log
        self.hook.log_intent(
            f"Autonomous mission finalized: {self.orchestrator.status.value}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS if self.orchestrator.status == MissionStatus.COMPLETED else EventStatus.WARNING,
            metadata={
                'status': self.orchestrator.status.value,
                'actions': len(self.orchestrator.action_history),
                'findings': len(self.orchestrator.findings),
                'approval_rate': dl_stats['approval_rate']
            }
        )
        
        print("\n" + "="*70 + "\n")


def demo_scenario_1():
    """Demo Scenario 1: Controlled Testing with HITL"""
    print("\n" + "="*70)
    print("📌 SCENARIO 1: Controlled Testing with HITL")
    print("="*70)
    print("\nOrchestrator proposes actions, human approves risky ones")
    print("="*70)
    
    system = IntegratedASI(
        agent_id="scenario1",
        enable_hitl=True
    )
    
    system.run_autonomous_mission(
        goal="Security assessment of web application",
        max_iterations=4
    )


def demo_scenario_2():
    """Demo Scenario 2: Emergency Stop on Tampering"""
    print("\n" + "="*70)
    print("📌 SCENARIO 2: Emergency Stop Demonstration")
    print("="*70)
    print("\nWhat happens when Vestigia detects tampering")
    print("="*70)
    
    print("\n⚠️  This would simulate ledger tampering detection")
    print("   If tampering detected → Emergency Stop → Mission Aborted")
    print("   (Run rogue_agent.py in another terminal to trigger)")


def main():
    """Main demo selector"""
    print("\n" + "="*70)
    print("🚀 INTEGRATED ASI SYSTEM - DEMO")
    print("="*70)
    print("\nDemonstrates complete ASI system with:")
    print("  • Autonomous decision-making (Orchestrator)")
    print("  • Policy enforcement (Decision Logic)")
    print("  • Human oversight (HITL)")
    print("  • Complete auditability (Vestigia)")
    print("="*70)
    
    print("\nAvailable scenarios:")
    print("  1. Controlled Testing with HITL (Interactive)")
    print("  2. Emergency Stop Demo (Info only)")
    
    choice = input("\nSelect scenario (1-2): ").strip()
    
    if choice == '1':
        demo_scenario_1()
    elif choice == '2':
        demo_scenario_2()
    else:
        print("Running default scenario...")
        demo_scenario_1()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

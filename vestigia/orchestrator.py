#!/usr/bin/env python3
"""
ASI Orchestrator - The Mission Brain

The autonomous agent that decides WHAT to test and WHEN.
Every decision is logged to Vestigia before execution.

This is the "Artist" that uses VerityFlux tools as "Paintbrushes".

Save as: vestigia/orchestrator.py
"""

import time
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime, UTC

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from event_hooks import VestigiaEventHook, IntentType, EventStatus


class MissionStatus(Enum):
    """Status of orchestrator mission"""
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class ActionType(Enum):
    """Types of actions the orchestrator can take"""
    # Reconnaissance
    PORT_SCAN = "PORT_SCAN"
    SERVICE_ENUM = "SERVICE_ENUMERATION"
    WEB_CRAWL = "WEB_CRAWL"
    
    # Exploitation
    SQL_INJECTION = "SQL_INJECTION"
    XSS_ATTACK = "XSS_ATTACK"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    
    # Post-Exploitation
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    
    # Defensive
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    REPORT = "REPORT"


class ASIOrchestrator:
    """
    Autonomous Security Intelligence Orchestrator
    
    The "brain" that decides which VerityFlux tools to use and when.
    Every decision is logged to Vestigia for complete auditability.
    
    Usage:
        orchestrator = ASIOrchestrator(agent_id="flux_agent_001")
        orchestrator.run_mission("Test web app at https://target.com")
    """
    
    def __init__(
        self,
        agent_id: str = "asi_orchestrator_001",
        enable_hitl: bool = True,
        auto_approve: bool = False
    ):
        self.agent_id = agent_id
        self.hook = VestigiaEventHook(agent_id=agent_id, enable_external_anchor=False)
        
        # HITL configuration
        self.enable_hitl = enable_hitl
        self.auto_approve = auto_approve
        
        # Mission state
        self.status = MissionStatus.PLANNING
        self.mission_goal = None
        self.action_history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        
        # Initialize
        self._log_initialization()
    
    def _log_initialization(self):
        """Log orchestrator initialization"""
        self.hook.log_intent(
            f"ASI Orchestrator initialized",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={
                'agent_id': self.agent_id,
                'hitl_enabled': self.enable_hitl,
                'auto_approve': self.auto_approve,
                'capabilities': [a.value for a in ActionType]
            }
        )
        
        print(f"\n🧠 ASI Orchestrator [{self.agent_id}] initialized")
        print(f"   HITL Mode: {'✅ Enabled' if self.enable_hitl else '❌ Disabled'}")
        print(f"   Auto-approve: {'✅ Yes' if self.auto_approve else '❌ No'}")
    
    def think(self, context: str) -> ActionType:
        """
        The "reasoning" step - decide what to do next
        
        This is where an LLM would analyze the situation and choose strategy.
        For now, it's rule-based logic.
        """
        print(f"\n🧠 THINKING: Analyzing context...")
        
        # Log the reasoning process
        self.hook.log_intent(
            "Strategizing next action",
            IntentType.PROMPT_SUBMISSION,
            EventStatus.SUCCESS,
            metadata={
                'context': context[:200],
                'mission_goal': self.mission_goal,
                'actions_taken': len(self.action_history)
            }
        )
        
        # Simple decision tree (in production, this would be LLM-driven)
        if len(self.action_history) == 0:
            decision = ActionType.PORT_SCAN
            reasoning = "No prior actions - starting with reconnaissance"
        
        elif len(self.action_history) == 1:
            decision = ActionType.SERVICE_ENUM
            reasoning = "Port scan complete - enumerating services"
        
        elif len(self.action_history) == 2:
            decision = ActionType.SQL_INJECTION
            reasoning = "Services identified - attempting SQL injection"
        
        else:
            decision = ActionType.REPORT
            reasoning = "Mission objectives achieved - generating report"
        
        print(f"   💡 Decision: {decision.value}")
        print(f"   📝 Reasoning: {reasoning}")
        
        # Log the decision
        self.hook.log_intent(
            f"Decision made: {decision.value}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={
                'action': decision.value,
                'reasoning': reasoning,
                'confidence': 0.85
            }
        )
        
        return decision
    
    def request_approval(self, action: ActionType, risk_level: str) -> bool:
        """
        Human-in-the-Loop approval gate
        
        Returns True if human approves, False if denied
        """
        if not self.enable_hitl:
            return True
        
        if self.auto_approve:
            print(f"   ⚡ AUTO-APPROVED (auto_approve=True)")
            return True
        
        # Log approval request
        self.hook.log_intent(
            f"Requesting human approval for {action.value}",
            IntentType.PERMISSION_CHECK,
            EventStatus.WARNING,
            metadata={
                'action': action.value,
                'risk_level': risk_level
            }
        )
        
        # Display approval prompt
        print("\n" + "="*70)
        print("🤚 HUMAN APPROVAL REQUIRED")
        print("="*70)
        print(f"   Action: {action.value}")
        print(f"   Risk Level: {risk_level}")
        print(f"   Mission: {self.mission_goal}")
        print(f"   Actions so far: {len(self.action_history)}")
        print("="*70)
        
        response = input("➡️  Approve this action? (yes/no/abort): ").lower().strip()
        
        if response in ['yes', 'y']:
            print("   ✅ APPROVED by human operator")
            
            # Log approval
            self.hook.log_intent(
                f"Action approved by human: {action.value}",
                IntentType.PERMISSION_CHECK,
                EventStatus.SUCCESS,
                metadata={'action': action.value, 'approved': True}
            )
            return True
        
        elif response in ['abort', 'a']:
            print("   🛑 MISSION ABORTED by human operator")
            
            # Log abort
            self.hook.log_security_event(
                f"Mission aborted by human during {action.value}",
                EventStatus.BLOCKED,
                threat_indicators={'action': action.value, 'reason': 'human_abort'}
            )
            
            self.status = MissionStatus.ABORTED
            return False
        
        else:
            print("   ❌ DENIED by human operator")
            
            # Log denial
            self.hook.log_intent(
                f"Action denied by human: {action.value}",
                IntentType.PERMISSION_CHECK,
                EventStatus.BLOCKED,
                metadata={'action': action.value, 'approved': False}
            )
            return False
    
    def act(self, action: ActionType) -> Dict[str, Any]:
        """
        Execute the decided action
        
        This is where VerityFlux tools would be called.
        Returns result dictionary.
        """
        # Determine risk level
        high_risk_actions = [
            ActionType.DATA_EXFILTRATION,
            ActionType.PRIVILEGE_ESCALATION,
            ActionType.LATERAL_MOVEMENT
        ]
        risk_level = "HIGH" if action in high_risk_actions else "MEDIUM"
        
        # Request approval if HITL enabled
        if not self.request_approval(action, risk_level):
            if self.status == MissionStatus.ABORTED:
                return {'status': 'aborted', 'reason': 'human_abort'}
            return {'status': 'denied', 'reason': 'human_denied'}
        
        print(f"\n🔥 EXECUTING: {action.value}")
        
        # Use context manager for automatic success/failure logging
        try:
            with self.hook.track_operation(
                f"Execute {action.value}",
                IntentType.TOOL_EXECUTION
            ):
                # Simulate action execution
                # In production, this would call actual VerityFlux tools
                result = self._simulate_action(action)
                
                print(f"   ✅ Action completed: {result['status']}")
                
                # Record in history
                self.action_history.append({
                    'timestamp': datetime.now(UTC).isoformat(),
                    'action': action.value,
                    'result': result,
                    'risk_level': risk_level
                })
                
                # If findings, record them
                if result.get('findings'):
                    self.findings.extend(result['findings'])
                
                return result
        
        except Exception as e:
            print(f"   ❌ Action failed: {e}")
            
            # Log failure
            self.hook.log_security_event(
                f"Action failed: {action.value}",
                EventStatus.FAILURE,
                threat_indicators={'action': action.value, 'error': str(e)}
            )
            
            return {'status': 'failed', 'error': str(e)}
    
    def _simulate_action(self, action: ActionType) -> Dict[str, Any]:
        """
        Simulate action execution
        
        In production, this would call actual VerityFlux tools:
        - PORT_SCAN → verity_port_scan.py
        - SQL_INJECTION → verity_sql_inject.py
        - etc.
        """
        time.sleep(1.5)  # Simulate work
        
        # Simulated results based on action type
        if action == ActionType.PORT_SCAN:
            return {
                'status': 'success',
                'findings': [
                    {'port': 80, 'state': 'open', 'service': 'http'},
                    {'port': 443, 'state': 'open', 'service': 'https'},
                    {'port': 3306, 'state': 'open', 'service': 'mysql'}
                ]
            }
        
        elif action == ActionType.SERVICE_ENUM:
            return {
                'status': 'success',
                'findings': [
                    {'service': 'Apache 2.4.41', 'version': '2.4.41', 'cves': ['CVE-2021-44790']},
                    {'service': 'MySQL', 'version': '5.7.33', 'auth': 'required'}
                ]
            }
        
        elif action == ActionType.SQL_INJECTION:
            return {
                'status': 'success',
                'findings': [
                    {'vulnerability': 'SQL Injection', 'location': '/login', 'severity': 'CRITICAL'}
                ]
            }
        
        elif action == ActionType.REPORT:
            return {
                'status': 'success',
                'summary': f'Mission completed with {len(self.findings)} findings'
            }
        
        else:
            return {'status': 'success', 'message': f'{action.value} executed'}
    
    def observe(self):
        """
        Observe current state and findings
        """
        print(f"\n👁️  OBSERVING: Current mission state")
        print(f"   Status: {self.status.value}")
        print(f"   Actions taken: {len(self.action_history)}")
        print(f"   Findings: {len(self.findings)}")
        
        # Log observation
        self.hook.log_intent(
            "Observing mission state",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={
                'status': self.status.value,
                'actions': len(self.action_history),
                'findings': len(self.findings)
            }
        )
    
    def run_mission(self, goal: str, max_iterations: int = 5):
        """
        Run autonomous mission with given goal
        
        The main "agentic loop":
        1. Think (decide what to do)
        2. Act (execute decision)
        3. Observe (check results)
        4. Repeat until goal achieved or max iterations
        """
        self.mission_goal = goal
        self.status = MissionStatus.EXECUTING
        
        print("\n" + "="*70)
        print(f"🎯 MISSION START: {goal}")
        print("="*70)
        
        # Log mission start
        self.hook.log_intent(
            f"Mission started: {goal}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={'goal': goal, 'max_iterations': max_iterations}
        )
        
        iteration = 0
        while iteration < max_iterations and self.status == MissionStatus.EXECUTING:
            iteration += 1
            
            print(f"\n📍 ITERATION {iteration}/{max_iterations}")
            print("-" * 70)
            
            # 1. THINK - Decide what to do
            context = f"Mission: {goal}. Actions taken: {len(self.action_history)}"
            action = self.think(context)
            
            # 2. ACT - Execute decision
            result = self.act(action)
            
            # Check if aborted
            if result.get('status') == 'aborted':
                break
            
            # 3. OBSERVE - Check state
            self.observe()
            
            # Check if mission complete
            if action == ActionType.REPORT:
                self.status = MissionStatus.COMPLETED
                break
            
            time.sleep(0.5)
        
        # Mission end
        self._finalize_mission()
    
    def _finalize_mission(self):
        """Finalize mission and generate report"""
        print("\n" + "="*70)
        print(f"🏁 MISSION {self.status.value}")
        print("="*70)
        
        print(f"\n📊 Mission Summary:")
        print(f"   Goal: {self.mission_goal}")
        print(f"   Status: {self.status.value}")
        print(f"   Actions taken: {len(self.action_history)}")
        print(f"   Findings: {len(self.findings)}")
        
        if self.findings:
            print(f"\n🔍 Key Findings:")
            for i, finding in enumerate(self.findings[:5], 1):
                print(f"   {i}. {finding}")
        
        # Log mission completion
        self.hook.log_intent(
            f"Mission finalized: {self.status.value}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS if self.status == MissionStatus.COMPLETED else EventStatus.FAILURE,
            metadata={
                'goal': self.mission_goal,
                'status': self.status.value,
                'actions': len(self.action_history),
                'findings': len(self.findings)
            }
        )
        
        print("\n" + "="*70 + "\n")


def main():
    """Demo usage of orchestrator"""
    print("\n" + "="*70)
    print("🧠 ASI ORCHESTRATOR - DEMO")
    print("="*70)
    print("\nThis demonstrates autonomous agent decision-making with HITL")
    print("="*70)
    
    # Example 1: HITL enabled (requires approval)
    print("\n📌 DEMO 1: Human-in-the-Loop Mode")
    orchestrator_hitl = ASIOrchestrator(
        agent_id="demo_hitl",
        enable_hitl=True,
        auto_approve=False
    )
    
    orchestrator_hitl.run_mission(
        goal="Test web application security at https://demo.testfire.net",
        max_iterations=4
    )
    
    # Example 2: Auto-approve mode (faster demo)
    print("\n\n📌 DEMO 2: Auto-Approve Mode")
    orchestrator_auto = ASIOrchestrator(
        agent_id="demo_auto",
        enable_hitl=True,
        auto_approve=True
    )
    
    orchestrator_auto.run_mission(
        goal="Scan internal network for vulnerabilities",
        max_iterations=3
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

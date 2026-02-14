#!/usr/bin/env python3
"""
Stateful ASI Orchestrator - State Machine Persistence

Enhanced orchestrator that can resume from crashes by reading Vestigia ledger.
Implements state persistence and recovery for production resilience.

Key Features:
- Reads last N entries on startup to restore state
- Recovers action history from ledger
- Resumes mission from last checkpoint
- Handles network interruptions gracefully

Save as: vestigia/stateful_orchestrator.py
"""

import time
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime, UTC

sys.path.insert(0, str(Path(__file__).parent))

from event_hooks import VestigiaEventHook, IntentType, EventStatus
from core.ledger_engine import VestigiaLedger


class MissionStatus(Enum):
    """Status of orchestrator mission"""
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    RECOVERING = "RECOVERING"


class ActionType(Enum):
    """Types of actions the orchestrator can take"""
    PORT_SCAN = "PORT_SCAN"
    SERVICE_ENUM = "SERVICE_ENUMERATION"
    WEB_CRAWL = "WEB_CRAWL"
    SQL_INJECTION = "SQL_INJECTION"
    XSS_ATTACK = "XSS_ATTACK"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    REPORT = "REPORT"


class StatefulOrchestrator:
    """
    Orchestrator with state persistence and recovery
    
    Can resume missions after crashes by reading Vestigia ledger.
    Implements checkpointing and state restoration.
    """
    
    def __init__(
        self,
        agent_id: str = "stateful_orchestrator",
        ledger_path: str = 'data/vestigia_ledger.json',
        enable_hitl: bool = True,
        auto_approve: bool = False,
        recovery_lookback: int = 10
    ):
        self.agent_id = agent_id
        self.ledger_path = ledger_path
        self.hook = VestigiaEventHook(agent_id=agent_id, enable_external_anchor=False)
        self.ledger = VestigiaLedger(ledger_path, enable_external_anchor=False)
        
        # HITL configuration
        self.enable_hitl = enable_hitl
        self.auto_approve = auto_approve
        
        # Mission state
        self.status = MissionStatus.PLANNING
        self.mission_goal = None
        self.action_history: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.recovery_lookback = recovery_lookback
        
        # Recovery state
        self.last_checkpoint = None
        self.recovered_from_crash = False
        
        # Attempt recovery on startup
        self._attempt_recovery()
        
        if not self.recovered_from_crash:
            self._log_initialization()
    
    def _attempt_recovery(self):
        """
        Attempt to recover state from Vestigia ledger
        
        Looks at last N entries to determine if we should resume a mission.
        """
        print("\n🔄 Checking for recoverable state...")
        
        try:
            # Query recent events for this agent
            recent_events = self.ledger.query_events(
                actor_id=self.agent_id,
                limit=self.recovery_lookback
            )
            
            if not recent_events:
                print("   ℹ️  No previous state found - starting fresh")
                return
            
            # Look for mission start and incomplete missions
            mission_started = False
            mission_completed = False
            actions_taken = []
            
            for event in recent_events:
                evidence = event.evidence if hasattr(event.evidence, 'get') else event.evidence
                
                # Handle evidence as dict or object
                if isinstance(evidence, dict):
                    summary = evidence.get('summary', '')
                    metadata = evidence.get('metadata', {})
                else:
                    summary = str(evidence)
                    metadata = {}
                
                if 'Mission started' in summary:
                    mission_started = True
                    if isinstance(metadata, dict):
                        self.mission_goal = metadata.get('goal')
                
                elif 'Mission finalized' in summary or 'Mission completed' in summary:
                    mission_completed = True
                
                elif event.action_type in [a.value for a in ActionType]:
                    actions_taken.append({
                        'action': event.action_type,
                        'timestamp': event.timestamp,
                        'status': event.status
                    })
            
            # Determine if recovery needed
            if mission_started and not mission_completed and actions_taken:
                self.recovered_from_crash = True
                self.action_history = actions_taken
                self.status = MissionStatus.RECOVERING
                
                print(f"\n🔄 STATE RECOVERY DETECTED")
                print(f"   Mission goal: {self.mission_goal or 'Unknown'}")
                print(f"   Actions recovered: {len(self.action_history)}")
                print(f"   Last action: {actions_taken[-1]['action']}")
                
                # Log recovery
                self.hook.log_security_event(
                    "State recovered from Vestigia ledger",
                    EventStatus.WARNING,
                    threat_indicators={
                        'recovered_actions': len(self.action_history),
                        'mission_goal': self.mission_goal
                    }
                )
                
                print("\n✅ State restored - mission can be resumed")
            else:
                print("   ℹ️  No incomplete missions found")
        
        except Exception as e:
            print(f"   ⚠️  Recovery failed: {e}")
            print("   ℹ️  Starting fresh session")
    
    def _log_initialization(self):
        """Log orchestrator initialization"""
        self.hook.log_intent(
            "Stateful Orchestrator initialized",
            IntentType.IDENTITY_VERIFICATION,
            EventStatus.SUCCESS,
            metadata={
                'agent_id': self.agent_id,
                'hitl_enabled': self.enable_hitl,
                'auto_approve': self.auto_approve,
                'recovery_enabled': True
            }
        )
        
        print(f"\n🧠 Stateful Orchestrator [{self.agent_id}] initialized")
        print(f"   HITL: {'✅ Enabled' if self.enable_hitl else '❌ Disabled'}")
        print(f"   Recovery: ✅ Enabled ({self.recovery_lookback} entries)")
    
    def create_checkpoint(self):
        """
        Create a checkpoint of current state
        
        Logs current mission state to Vestigia for future recovery.
        """
        checkpoint_data = {
            'mission_goal': self.mission_goal,
            'status': self.status.value,
            'actions_completed': len(self.action_history),
            'findings_count': len(self.findings),
            'timestamp': datetime.now(UTC).isoformat()
        }
        
        self.hook.log_intent(
            "Mission checkpoint created",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata=checkpoint_data
        )
        
        self.last_checkpoint = checkpoint_data
        print(f"   💾 Checkpoint saved: {len(self.action_history)} actions completed")
    
    def think(self, context: str) -> ActionType:
        """The reasoning step - decide what to do next"""
        print(f"\n🧠 THINKING: Analyzing context...")
        
        # Log reasoning
        self.hook.log_intent(
            "Strategizing next action",
            IntentType.PROMPT_SUBMISSION,
            EventStatus.SUCCESS,
            metadata={
                'context': context[:200],
                'mission_goal': self.mission_goal,
                'actions_taken': len(self.action_history),
                'recovered': self.recovered_from_crash
            }
        )
        
        # Decision tree (in production, LLM-driven)
        if len(self.action_history) == 0:
            decision = ActionType.PORT_SCAN
            reasoning = "Starting reconnaissance"
        elif len(self.action_history) == 1:
            decision = ActionType.SERVICE_ENUM
            reasoning = "Port scan complete - enumerating services"
        elif len(self.action_history) == 2:
            decision = ActionType.SQL_INJECTION
            reasoning = "Services identified - testing SQL injection"
        else:
            decision = ActionType.REPORT
            reasoning = "Mission objectives achieved - generating report"
        
        print(f"   💡 Decision: {decision.value}")
        print(f"   📝 Reasoning: {reasoning}")
        
        # Log decision
        self.hook.log_intent(
            f"Decision: {decision.value}",
            IntentType.TOOL_EXECUTION,
            EventStatus.SUCCESS,
            metadata={'action': decision.value, 'reasoning': reasoning}
        )
        
        return decision
    
    def request_approval(self, action: ActionType, risk_level: str) -> bool:
        """Human-in-the-Loop approval gate"""
        if not self.enable_hitl or self.auto_approve:
            return True
        
        # Log approval request
        self.hook.log_intent(
            f"Requesting approval: {action.value}",
            IntentType.PERMISSION_CHECK,
            EventStatus.WARNING,
            metadata={'action': action.value, 'risk': risk_level}
        )
        
        print("\n" + "="*70)
        print("🤚 HUMAN APPROVAL REQUIRED")
        print("="*70)
        print(f"   Action: {action.value}")
        print(f"   Risk: {risk_level}")
        print(f"   Mission: {self.mission_goal}")
        print(f"   Progress: {len(self.action_history)} actions completed")
        print("="*70)
        
        response = input("➡️  Approve? (yes/no/abort): ").lower().strip()
        
        if response in ['yes', 'y']:
            print("   ✅ APPROVED")
            self.hook.log_intent(
                f"Action approved: {action.value}",
                IntentType.PERMISSION_CHECK,
                EventStatus.SUCCESS,
                metadata={'action': action.value}
            )
            return True
        elif response in ['abort', 'a']:
            print("   🛑 MISSION ABORTED")
            self.status = MissionStatus.ABORTED
            return False
        else:
            print("   ❌ DENIED")
            return False
    
    def act(self, action: ActionType) -> Dict[str, Any]:
        """Execute the decided action"""
        risk_level = "HIGH" if action.value in ['DATA_EXFILTRATION', 'PRIVILEGE_ESCALATION'] else "MEDIUM"
        
        if not self.request_approval(action, risk_level):
            if self.status == MissionStatus.ABORTED:
                return {'status': 'aborted'}
            return {'status': 'denied'}
        
        print(f"\n🔥 EXECUTING: {action.value}")
        
        try:
            with self.hook.track_operation(f"Execute {action.value}", IntentType.TOOL_EXECUTION):
                result = self._simulate_action(action)
                
                print(f"   ✅ Action completed: {result['status']}")
                
                # Record in history
                self.action_history.append({
                    'timestamp': datetime.now(UTC).isoformat(),
                    'action': action.value,
                    'result': result,
                    'risk_level': risk_level
                })
                
                if result.get('findings'):
                    self.findings.extend(result['findings'])
                
                # Create checkpoint every 2 actions
                if len(self.action_history) % 2 == 0:
                    self.create_checkpoint()
                
                return result
        
        except Exception as e:
            print(f"   ❌ Action failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _simulate_action(self, action: ActionType) -> Dict[str, Any]:
        """Simulate action execution"""
        time.sleep(1.5)
        
        if action == ActionType.PORT_SCAN:
            return {
                'status': 'success',
                'findings': [
                    {'port': 80, 'state': 'open', 'service': 'http'},
                    {'port': 443, 'state': 'open', 'service': 'https'}
                ]
            }
        elif action == ActionType.SERVICE_ENUM:
            return {
                'status': 'success',
                'findings': [
                    {'service': 'Apache 2.4.41', 'cves': ['CVE-2021-44790']}
                ]
            }
        elif action == ActionType.SQL_INJECTION:
            return {
                'status': 'success',
                'findings': [
                    {'vulnerability': 'SQL Injection', 'severity': 'CRITICAL'}
                ]
            }
        else:
            return {'status': 'success', 'message': f'{action.value} executed'}
    
    def observe(self):
        """Observe current state"""
        print(f"\n👁️  OBSERVING: Mission state")
        print(f"   Status: {self.status.value}")
        print(f"   Actions: {len(self.action_history)}")
        print(f"   Findings: {len(self.findings)}")
    
    def run_mission(self, goal: str, max_iterations: int = 5, resume: bool = True):
        """Run mission with state persistence"""
        
        # Check if resuming
        if resume and self.recovered_from_crash:
            print("\n" + "="*70)
            print("🔄 RESUMING MISSION FROM CHECKPOINT")
            print("="*70)
            self.status = MissionStatus.EXECUTING
        else:
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
        
        # Calculate starting iteration based on recovery
        start_iteration = len(self.action_history) if resume else 0
        
        for iteration in range(start_iteration, max_iterations):
            if self.status != MissionStatus.EXECUTING:
                break
            
            print(f"\n📍 ITERATION {iteration + 1}/{max_iterations}")
            print("-" * 70)
            
            context = f"Mission: {goal}. Actions: {len(self.action_history)}"
            action = self.think(context)
            result = self.act(action)
            
            if result.get('status') == 'aborted':
                break
            
            self.observe()
            
            if action == ActionType.REPORT:
                self.status = MissionStatus.COMPLETED
                break
            
            time.sleep(0.5)
        
        self._finalize_mission()
    
    def _finalize_mission(self):
        """Finalize mission"""
        print("\n" + "="*70)
        print(f"🏁 MISSION {self.status.value}")
        print("="*70)
        
        print(f"\n📊 Mission Summary:")
        print(f"   Goal: {self.mission_goal}")
        print(f"   Status: {self.status.value}")
        print(f"   Actions: {len(self.action_history)}")
        print(f"   Findings: {len(self.findings)}")
        
        # Log completion
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


def demo_recovery():
    """Demonstrate state recovery"""
    print("\n" + "="*70)
    print("🔄 STATEFUL ORCHESTRATOR - RECOVERY DEMO")
    print("="*70)
    
    # Part 1: Start mission, simulate crash
    print("\n📌 PART 1: Starting mission (will simulate crash)")
    orchestrator1 = StatefulOrchestrator(
        agent_id="recovery_demo",
        enable_hitl=False,
        auto_approve=True
    )
    
    print("\n   Starting mission, will 'crash' after 2 actions...")
    orchestrator1.mission_goal = "Test security assessment"
    orchestrator1.status = MissionStatus.EXECUTING
    
    # Simulate 2 actions
    orchestrator1.act(ActionType.PORT_SCAN)
    orchestrator1.act(ActionType.SERVICE_ENUM)
    
    print("\n   💥 SIMULATED CRASH (orchestrator1 destroyed)")
    del orchestrator1
    
    # Part 2: Create new orchestrator, recover state
    print("\n📌 PART 2: Creating new orchestrator (recovery attempt)")
    orchestrator2 = StatefulOrchestrator(
        agent_id="recovery_demo",
        enable_hitl=False,
        auto_approve=True
    )
    
    if orchestrator2.recovered_from_crash:
        print("\n✅ RECOVERY SUCCESSFUL!")
        print(f"   Can resume mission: {orchestrator2.mission_goal}")
        print(f"   Actions recovered: {len(orchestrator2.action_history)}")
        
        # Resume mission
        orchestrator2.run_mission("Test security assessment", max_iterations=4, resume=True)
    else:
        print("\n❌ No state to recover")


if __name__ == '__main__':
    try:
        demo_recovery()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

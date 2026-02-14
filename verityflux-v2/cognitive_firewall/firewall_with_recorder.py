#!/usr/bin/env python3
"""
Enhanced Cognitive Firewall with Flight Recorder Integration

Adds complete state logging for compliance and forensic analysis.
"""

from typing import Dict, Any, Optional
import psutil
import os

from .firewall import CognitiveFirewall, AgentAction, FirewallDecision, FirewallAction
from .flight_recorder import FlightRecorder

class CognitiveFirewallWithRecorder(CognitiveFirewall):
    """
    Cognitive Firewall with integrated Flight Recorder.
    
    Automatically captures state snapshots for every decision.
    """
    
    def __init__(
        self,
        intent_validator=None,
        permission_engine=None,
        impact_analyzer=None,
        config: Optional[Dict] = None,
        enable_flight_recorder: bool = True,
        log_dir: str = "flight_logs"
    ):
        # EnhancedCognitiveFirewall expects only config
        super().__init__(config)
        
        # Initialize Flight Recorder
        self.flight_recorder = FlightRecorder(log_dir=log_dir) if enable_flight_recorder else None
        self.enable_recording = enable_flight_recorder
    
    def evaluate(self, agent_action: AgentAction) -> FirewallDecision:
        """
        Evaluate action and record complete state snapshot.
        """
        
        # Capture system state BEFORE evaluation
        system_state = self._capture_system_state()
        
        # Get RAG context if available
        rag_context = self._extract_rag_context(agent_action)
        
        # Run normal firewall evaluation
        decision = super().evaluate(agent_action)
        
        # Record the event
        if self.enable_recording and self.flight_recorder:
            event_id = self.flight_recorder.record_event(
                event_type='firewall_decision',
                agent_action=agent_action,
                firewall_decision=decision,
                system_state=system_state,
                rag_context=rag_context
            )
            
            # Record violation if action was blocked
            if decision.action in [FirewallAction.BLOCK, FirewallAction.REQUIRE_APPROVAL]:
                severity = 'critical' if decision.risk_score >= 80 else 'high' if decision.risk_score >= 60 else 'medium'
                
                self.flight_recorder.record_violation(
                    violation_type=decision.violations[0] if decision.violations else 'unknown',
                    severity=severity,
                    agent_action=agent_action,
                    firewall_decision=decision,
                    context={
                        'agent_history': self.action_log[-5:],  # Last 5 actions
                        'environment': agent_action.context.get('environment', 'unknown'),
                        'recent_actions': [log for log in self.action_log if log['agent_id'] == agent_action.agent_id][-3:]
                    }
                )
        
        return decision
    
    def _capture_system_state(self) -> Dict[str, Any]:
        """
        Capture current system state for forensics.
        
        Includes: memory, CPU, disk, running processes
        """
        
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            disk = psutil.disk_usage('/')
            
            return {
                'memory': {
                    'total_mb': memory.total / (1024**2),
                    'available_mb': memory.available / (1024**2),
                    'used_percent': memory.percent
                },
                'cpu': {
                    'percent': cpu_percent,
                    'count': psutil.cpu_count()
                },
                'disk': {
                    'total_gb': disk.total / (1024**3),
                    'free_gb': disk.free / (1024**3),
                    'used_percent': disk.percent
                },
                'process': {
                    'pid': os.getpid(),
                    'threads': psutil.Process().num_threads()
                }
            }
        except Exception as e:
            return {'error': str(e), 'available': False}
    
    def _extract_rag_context(self, agent_action: AgentAction) -> list:
        """
        Extract RAG context if available in agent action.
        
        In production, this would query the vector DB for retrieved chunks.
        """
        
        # Check if RAG context is in agent action context
        if 'rag_chunks' in agent_action.context:
            return agent_action.context['rag_chunks'][:5]  # Top 5 chunks
        
        # Simulate RAG retrieval for testing
        if agent_action.context.get('has_rag', False):
            return [
                {'chunk_id': 'chunk_001', 'content': 'Simulated RAG context chunk 1...', 'score': 0.95},
                {'chunk_id': 'chunk_002', 'content': 'Simulated RAG context chunk 2...', 'score': 0.87},
                {'chunk_id': 'chunk_003', 'content': 'Simulated RAG context chunk 3...', 'score': 0.82}
            ]
        
        return []
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session from Flight Recorder"""
        if self.flight_recorder:
            return self.flight_recorder.get_session_summary()
        return {}
    
    def export_audit_logs(self, start_date, end_date, output_file=None) -> str:
        """Export logs for compliance audit"""
        if self.flight_recorder:
            return self.flight_recorder.export_for_audit(start_date, end_date, output_file)
        return ""

__all__ = ['CognitiveFirewallWithRecorder']

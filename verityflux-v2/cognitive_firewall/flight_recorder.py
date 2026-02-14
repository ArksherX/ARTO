#!/usr/bin/env python3
"""
Enhanced Flight Recorder for Enterprise Firewall

Records all enterprise firewall decisions with full context
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import asdict


class EnterpriseFlightRecorder:
    """
    Records all firewall decisions with enterprise metadata
    """
    
    def __init__(self, log_dir: str = "flight_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create session log
        self.session_file = self.log_dir / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        
    def record_decision(self, 
                       agent_action,  # AgentAction
                       decision,       # FirewallDecision
                       execution_time_ms: float = 0) -> None:
        """
        Record a firewall decision with full enterprise context
        
        Args:
            agent_action: The original agent action
            decision: The firewall decision
            execution_time_ms: Time taken to evaluate (milliseconds)
        """
        
        # Extract vulnerability matches from context
        vuln_matches = decision.context.get('vulnerability_matches', 0)
        risk_breakdown = decision.context.get('risk_breakdown', {})
        
        # Build comprehensive log entry
        log_entry = {
            # Timestamp
            'timestamp': datetime.now().isoformat(),
            
            # Agent information
            'agent_id': agent_action.agent_id,
            'tool_name': agent_action.tool_name,
            'original_goal': agent_action.original_goal,
            
            # Decision
            'firewall_decision': {
                'action': decision.action.value,
                'risk_score': decision.risk_score,
                'tier': decision.context.get('tier', 'UNKNOWN'),
                'confidence': decision.confidence,
                'reasoning': decision.reasoning
            },
            
            # Enterprise metrics (NEW)
            'enterprise_analysis': {
                'vulnerability_matches': vuln_matches,
                'deception_detected': decision.context.get('deception_detected', False),
                'risk_breakdown': risk_breakdown,
                'violations': decision.violations,
                'recommendations': decision.recommendations
            },
            
            # Performance
            'execution_time_ms': execution_time_ms,
            
            # Full context (for forensics)
            'reasoning_chain': agent_action.reasoning_chain,
            'parameters': agent_action.parameters,
            'context': agent_action.context
        }
        
        # Write to log file (JSONL format)
        with open(self.session_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def record_event(
        self,
        event_type: str,
        agent_action,
        firewall_decision,
        system_state: Optional[Dict[str, Any]] = None,
        rag_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Compatibility wrapper expected by firewall_with_recorder."""
        self.record_decision(agent_action, firewall_decision, execution_time_ms=0)
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent log entries"""
        logs = []
        
        if not self.session_file.exists():
            return logs
        
        with open(self.session_file, 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    pass
        
        return logs[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get session statistics"""
        logs = self.get_recent_logs(limit=10000)
        
        if not logs:
            return {
                'total_actions': 0,
                'blocked': 0,
                'allowed': 0,
                'requires_approval': 0
            }
        
        stats = {
            'total_actions': len(logs),
            'blocked': sum(1 for log in logs if log['firewall_decision']['action'] == 'block'),
            'allowed': sum(1 for log in logs if log['firewall_decision']['action'] == 'allow'),
            'requires_approval': sum(1 for log in logs if log['firewall_decision']['action'] == 'require_approval'),
            'avg_risk_score': sum(log['firewall_decision']['risk_score'] for log in logs) / len(logs),
            'deceptions_detected': sum(1 for log in logs if log['enterprise_analysis']['deception_detected']),
            'vulnerability_alerts': sum(log['enterprise_analysis']['vulnerability_matches'] for log in logs)
        }
        
        return stats

    def get_session_summary(self) -> Dict[str, Any]:
        """Return lightweight session summary used by tests/UI."""
        stats = self.get_statistics()
        return {
            "session_id": self.session_file.stem,
            "total_events": stats.get("total_actions", 0),
            "stats": stats,
        }


# Backwards-compatible alias
FlightRecorder = EnterpriseFlightRecorder

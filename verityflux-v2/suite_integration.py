"""
VerityFlux - Suite Integration Module
Logs firewall decisions to shared audit log
"""

import os
from datetime import datetime
from pathlib import Path

class SuiteIntegration:
    def __init__(self):
        self.audit_log = os.getenv('SUITE_AUDIT_LOG',
                                   Path(__file__).parent.parent / "shared_state" / "shared_audit.log")
    
    def log_scan_started(self, target: str):
        """Log scan initiation"""
        self._write_log("SCAN_STARTED", f"Target={target}")
    
    def log_threat_detected(self, threat_id: str, risk_score: float, action: str):
        """Log threat detection"""
        self._write_log("THREAT_DETECTED",
                       f"ThreatID={threat_id}, RiskScore={risk_score}, Action={action}")
    
    def log_action_blocked(self, agent_id: str, tool: str, reason: str):
        """Log blocked action"""
        self._write_log("ACTION_BLOCKED",
                       f"Agent={agent_id}, Tool={tool}, Reason={reason}")
    
    def log_action_allowed(self, agent_id: str, tool: str, risk_score: float):
        """Log allowed action"""
        self._write_log("ACTION_ALLOWED",
                       f"Agent={agent_id}, Tool={tool}, RiskScore={risk_score}")
    
    def _write_log(self, event_type: str, details: str):
        """Write to shared audit log"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"{timestamp} | VERITYFLUX | {event_type} | {details}\n"
        
        try:
            with open(self.audit_log, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"⚠️  Failed to write to shared log: {e}")

# Global instance
suite_logger = SuiteIntegration()

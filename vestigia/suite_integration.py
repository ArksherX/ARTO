"""
Vestigia - Suite Integration Module
Monitors shared audit log for integrity
"""

import os
from datetime import datetime
from pathlib import Path

class SuiteIntegration:
    def __init__(self):
        self.audit_log = os.getenv('SUITE_AUDIT_LOG',
                                   Path(__file__).parent.parent / "shared_state" / "shared_audit.log")
    
    def read_shared_events(self):
        """Read events from shared audit log"""
        try:
            if not os.path.exists(self.audit_log):
                return []
            
            with open(self.audit_log, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"⚠️  Failed to read shared log: {e}")
            return []
    
    def log_kill_switch_activated(self, pid: str, reason: str):
        """Log kill-switch activation"""
        self._write_log("KILL_SWITCH_ACTIVATED",
                       f"PID={pid}, Reason={reason}")
    
    def log_ledger_verified(self, event_count: int):
        """Log ledger verification"""
        self._write_log("LEDGER_VERIFIED",
                       f"Events={event_count}")
    
    def log_integrity_violation(self, details: str):
        """Log integrity violation"""
        self._write_log("INTEGRITY_VIOLATION",
                       f"Details={details}")
    
    def _write_log(self, event_type: str, details: str):
        """Write to shared audit log"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"{timestamp} | VESTIGIA | {event_type} | {details}\n"
        
        try:
            with open(self.audit_log, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"⚠️  Failed to write to shared log: {e}")

# Global instance
suite_logger = SuiteIntegration()

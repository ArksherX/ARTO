"""
Tessera - Suite Integration Module
Logs events to shared audit log
"""

import os
from datetime import datetime
from pathlib import Path

class SuiteIntegration:
    def __init__(self):
        self.audit_log = os.getenv('SUITE_AUDIT_LOG', 
                                   Path(__file__).parent.parent / "shared_state" / "shared_audit.log")
    
    def log_token_issued(self, agent_id: str, token_id: str, tool: str):
        """Log token issuance to shared log"""
        self._write_log("TOKEN_ISSUED", 
                       f"Agent={agent_id}, Tool={tool}, TokenID={token_id}")
    
    def log_token_validated(self, token_id: str, result: str):
        """Log token validation"""
        self._write_log("TOKEN_VALIDATED", 
                       f"TokenID={token_id}, Result={result}")
    
    def log_token_revoked(self, token_id: str, reason: str):
        """Log token revocation"""
        self._write_log("TOKEN_REVOKED", 
                       f"TokenID={token_id}, Reason={reason}")
    
    def _write_log(self, event_type: str, details: str):
        """Write to shared audit log"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"{timestamp} | TESSERA | {event_type} | {details}\n"
        
        try:
            with open(self.audit_log, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"⚠️  Failed to write to shared log: {e}")

# Global instance
suite_logger = SuiteIntegration()

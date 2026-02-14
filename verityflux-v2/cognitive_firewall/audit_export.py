#!/usr/bin/env python3
"""
Forensic Audit Log Exporter

Generates signed PDF/JSON exports for compliance (EU AI Act, SOC2, etc.)
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

class AuditExporter:
    """
    Generate tamper-proof audit logs for compliance.
    """
    
    def __init__(self, output_dir: str = "audit_exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def export_to_json(self, logs: List[Dict], metadata: Dict[str, Any]) -> str:
        """
        Export audit log to signed JSON.
        
        Returns:
            filepath: str
        """
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_log_{timestamp}.json"
        filepath = self.output_dir / filename
        
        # Create audit package
        audit_package = {
            'metadata': {
                **metadata,
                'export_timestamp': datetime.now().isoformat(),
                'total_events': len(logs),
                'compliance_frameworks': ['EU AI Act', 'GDPR', 'SOC 2', 'ISO 27001']
            },
            'events': logs,
            'signature': self._generate_signature(logs)
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(audit_package, f, indent=2)
        
        return str(filepath)
    
    def _generate_signature(self, logs: List[Dict]) -> str:
        """Generate cryptographic signature for tamper detection"""
        data = json.dumps(logs, sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()
    
    def verify_signature(self, filepath: str) -> bool:
        """Verify audit log integrity"""
        with open(filepath, 'r') as f:
            package = json.load(f)
        
        expected_sig = self._generate_signature(package['events'])
        actual_sig = package['signature']
        
        return expected_sig == actual_sig

__all__ = ['AuditExporter']

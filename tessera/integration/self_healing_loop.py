#!/usr/bin/env python3
"""
Self-Healing Security Loop
Automatically blacklists agents that trigger honey-tools or behave suspiciously
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class SecurityIncident:
    agent_id: str
    incident_type: str
    severity: str  # low, medium, high, critical
    details: str
    timestamp: datetime

class SelfHealingLoop:
    """Automatic response to suspicious agent behavior"""
    
    # Honey-tools: Tools that exist but should NEVER be called
    HONEY_TOOLS = [
        'export_entire_database',
        'delete_all_data',
        'grant_admin_access',
        'disable_firewall',
        'exfiltrate_secrets'
    ]
    
    def __init__(self, registry_path: str = "data/tessera_registry.json"):
        self.registry_path = registry_path
        self.incident_log = []
        self.blacklist = set()
    
    def check_tool_request(self, agent_id: str, tool: str) -> tuple[bool, str]:
        """
        Check if tool request is suspicious
        
        Returns:
            (is_safe, reason)
        """
        # Check honey-tool
        if tool in self.HONEY_TOOLS:
            incident = SecurityIncident(
                agent_id=agent_id,
                incident_type='HONEY_TOOL_TRIGGERED',
                severity='critical',
                details=f"Agent attempted to use honey-tool: {tool}",
                timestamp=datetime.now()
            )
            self._handle_incident(incident)
            return False, f"🍯 HONEY-TOOL TRIGGERED: {tool}"
        
        return True, "Safe"
    
    def report_verityflux_threat(
        self,
        agent_id: str,
        threat_type: str,
        risk_score: float,
        details: str
    ):
        """Called by VerityFlux when suspicious behavior detected"""
        severity = self._calculate_severity(risk_score)
        
        incident = SecurityIncident(
            agent_id=agent_id,
            incident_type=f'VERITYFLUX_{threat_type}',
            severity=severity,
            details=details,
            timestamp=datetime.now()
        )
        
        self._handle_incident(incident)
    
    def _handle_incident(self, incident: SecurityIncident):
        """Automatic incident response"""
        self.incident_log.append(incident)
        
        print(f"\n🚨 SECURITY INCIDENT DETECTED")
        print(f"   Agent: {incident.agent_id}")
        print(f"   Type: {incident.incident_type}")
        print(f"   Severity: {incident.severity.upper()}")
        print(f"   Details: {incident.details}")
        
        # Automatic responses based on severity
        if incident.severity in ['critical', 'high']:
            self._blacklist_agent(incident.agent_id, incident.details)
            self._revoke_all_tokens(incident.agent_id)
            self._notify_ciso(incident)
        elif incident.severity == 'medium':
            self._suspend_agent(incident.agent_id)
        
        # Log to file
        self._log_incident(incident)
    
    def _blacklist_agent(self, agent_id: str, reason: str):
        """Add agent to permanent blacklist"""
        self.blacklist.add(agent_id)
        
        print(f"   🚫 BLACKLISTED: {agent_id}")
        print(f"   Reason: {reason}")
        
        # Update registry
        self._update_registry_status(agent_id, 'blacklisted', reason)
    
    def _suspend_agent(self, agent_id: str):
        """Temporarily suspend agent"""
        print(f"   ⏸️  SUSPENDED: {agent_id}")
        self._update_registry_status(agent_id, 'suspended', 'Automatic suspension due to suspicious activity')
    
    def _revoke_all_tokens(self, agent_id: str):
        """Revoke all tokens for this agent"""
        print(f"   🔑 REVOKING ALL TOKENS: {agent_id}")
        # This would integrate with RevocationList
        # For now, just log it
    
    def _notify_ciso(self, incident: SecurityIncident):
        """Send alert to CISO"""
        print(f"   📧 ALERT SENT TO CISO")
        # In production, this would send webhook/email
    
    def _update_registry_status(self, agent_id: str, status: str, reason: str):
        """Update agent status in registry"""
        try:
            with open(self.registry_path, 'r') as f:
                registry = json.load(f)
            
            if agent_id in registry:
                registry[agent_id]['status'] = status
                registry[agent_id]['status_reason'] = reason
                registry[agent_id]['last_updated'] = datetime.now().isoformat()
                
                with open(self.registry_path, 'w') as f:
                    json.dump(registry, f, indent=2)
                
                print(f"   ✅ Registry updated: {agent_id} → {status}")
        except Exception as e:
            print(f"   ⚠️  Failed to update registry: {e}")
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Convert risk score to severity level"""
        if risk_score >= 90:
            return 'critical'
        elif risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _log_incident(self, incident: SecurityIncident):
        """Log incident to file"""
        log_file = 'logs/security_incidents.jsonl'
        os.makedirs('logs', exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps({
                'agent_id': incident.agent_id,
                'type': incident.incident_type,
                'severity': incident.severity,
                'details': incident.details,
                'timestamp': incident.timestamp.isoformat()
            }) + '\n')

# ============================================================================
# DEMO: Honey-Tool Detection
# ============================================================================
if __name__ == "__main__":
    loop = SelfHealingLoop()
    
    print("🍯 HONEY-TOOL DETECTION DEMO")
    print("=" * 60)
    
    # Scenario 1: Normal tool usage
    print("\n1️⃣  Agent requests normal tool (read_csv)")
    safe, reason = loop.check_tool_request('agent_financial_bot_01', 'read_csv')
    print(f"   Result: {reason}")
    
    # Scenario 2: Honey-tool triggered
    print("\n2️⃣  Agent requests honey-tool (export_entire_database)")
    safe, reason = loop.check_tool_request('agent_financial_bot_01', 'export_entire_database')
    print(f"   Result: {reason}")
    
    # Scenario 3: VerityFlux reports suspicious behavior
    print("\n3️⃣  VerityFlux reports deceptive reasoning")
    loop.report_verityflux_threat(
        agent_id='agent_financial_bot_01',
        threat_type='DECEPTIVE_REASONING',
        risk_score=95.0,
        details='Agent provided contradictory explanations for SQL query'
    )
    
    print("\n" + "=" * 60)
    print(f"📊 Total Incidents: {len(loop.incident_log)}")
    print(f"🚫 Blacklisted Agents: {len(loop.blacklist)}")

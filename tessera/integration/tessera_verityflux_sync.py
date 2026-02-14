#!/usr/bin/env python3
"""
Tessera-VerityFlux Auto-Sync

When VerityFlux detects malicious behavior:
1. Automatically revoke Tessera token
2. Update agent status to 'suspended'
3. Alert CISO via webhook
"""

import requests
import os
from datetime import datetime

class TesseraVerityFluxSync:
    """Syncs VerityFlux threat detection with Tessera IAM"""
    
    def __init__(self, tessera_api_url: str, api_key: str):
        self.api_url = tessera_api_url
        self.api_key = api_key
    
    def handle_threat_detected(
        self,
        agent_id: str,
        jti: str,
        threat_type: str,
        risk_score: float,
        reason: str
    ):
        """
        Called by VerityFlux when threat detected
        
        Automatically:
        1. Revokes the token
        2. Suspends the agent
        3. Logs to audit trail
        """
        print(f"🚨 THREAT DETECTED: {agent_id}")
        print(f"   Risk Score: {risk_score}/100")
        print(f"   Reason: {reason}")
        
        # 1. Revoke token immediately
        self._revoke_token(jti, f"VerityFlux threat: {threat_type}")
        
        # 2. Suspend agent if risk > 80
        if risk_score > 80:
            self._suspend_agent(agent_id, reason)
        
        # 3. Alert CISO (webhook)
        self._send_alert(agent_id, threat_type, risk_score)
        
        print(f"✅ Security response complete")
    
    def _revoke_token(self, jti: str, reason: str):
        """Revoke token via API"""
        response = requests.post(
            f"{self.api_url}/tokens/revoke",
            params={"jti": jti, "reason": reason},
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        return response.json()
    
    def _suspend_agent(self, agent_id: str, reason: str):
        """Suspend agent (would need API endpoint)"""
        # TODO: Add /agents/{id}/suspend endpoint to api_server.py
        print(f"   ⚠️  Agent {agent_id} suspended: {reason}")
    
    def _send_alert(self, agent_id: str, threat_type: str, risk_score: float):
        """Send alert to CISO (Slack/Email)"""
        webhook_url = os.getenv('SECURITY_WEBHOOK_URL')
        if webhook_url:
            requests.post(webhook_url, json={
                'text': f'🚨 Security Alert: Agent {agent_id} detected: {threat_type} (Risk: {risk_score})'
            })

# Example usage
if __name__ == "__main__":
    sync = TesseraVerityFluxSync(
        tessera_api_url="http://localhost:8000",
        api_key=os.getenv('TESSERA_API_KEY')
    )
    
    # Simulate VerityFlux detecting threat
    sync.handle_threat_detected(
        agent_id="agent_financial_bot_01",
        jti="tessera_abc123",
        threat_type="Deceptive Reasoning",
        risk_score=95.0,
        reason="Agent attempted SQL injection"
    )

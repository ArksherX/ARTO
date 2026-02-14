#!/usr/bin/env python3
"""
Human-in-the-Loop (HITL) Workflow

Sends approval requests to Slack/Teams for medium-risk actions.
"""

import requests
from typing import Dict, Any, Optional
from datetime import datetime

class HITLWorkflow:
    """
    Human-in-the-Loop workflow integration.
    
    Pauses agent and requests human approval via Slack/Teams.
    """
    
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        self.pending_approvals = {}
    
    def request_approval(self, action: Dict[str, Any], decision: Dict[str, Any]) -> str:
        """
        Request human approval for action.
        
        Returns:
            approval_id: str
        """
        
        approval_id = f"approval_{int(datetime.now().timestamp())}"
        
        # Create approval request
        message = {
            "text": "🚨 VerityFlux: Action Requires Approval",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ VerityFlux Security Alert"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Agent ID:*\n{action['agent_id']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Tool:*\n{action['tool_name']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Risk Score:*\n{decision['risk_score']:.0f}/100"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Goal:*\n{action['original_goal']}"
                        }
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "✅ Approve"
                            },
                            "style": "primary",
                            "value": approval_id
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "❌ Deny"
                            },
                            "style": "danger",
                            "value": approval_id
                        }
                    ]
                }
            ]
        }
        
        # Send to Slack/Teams
        try:
            if self.webhook_url and "YOUR/WEBHOOK/URL" not in self.webhook_url:
                response = requests.post(self.webhook_url, json=message)
                print(f"✅ Approval request sent to Slack (Status: {response.status_code})")
        except Exception as e:
            print(f"⚠️  Could not send to Slack: {e}")
        
        # Store pending approval
        self.pending_approvals[approval_id] = {
            'action': action,
            'decision': decision,
            'status': 'pending',
            'requested_at': datetime.now().isoformat()
        }
        
        return approval_id
    
    def check_approval(self, approval_id: str) -> str:
        """
        Check status of approval request.
        
        Returns:
            'approved'|'denied'|'pending'
        """
        
        if approval_id in self.pending_approvals:
            return self.pending_approvals[approval_id]['status']
        return 'unknown'

__all__ = ['HITLWorkflow']

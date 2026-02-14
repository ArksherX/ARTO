#!/usr/bin/env python3
"""
HITL Notification Handlers

Send approval requests via Slack, Email, etc.
"""

import os
from typing import Optional
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class SlackNotifier:
    """Send HITL approvals to Slack"""
    
    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize Slack notifier
        
        Args:
            webhook_url: Slack webhook URL (or set SLACK_WEBHOOK_URL env var)
        """
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL')
    
    def __call__(self, request):
        """Send notification"""
        if not self.webhook_url:
            return
        
        # Build Slack message
        message = {
            "text": f"🚨 *HITL Approval Required*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 Approval Required: {request.request_id}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:*\n{request.agent_id}"},
                        {"type": "mrkdwn", "text": f"*Tool:*\n{request.tool_name}"},
                        {"type": "mrkdwn", "text": f"*Risk:*\n{request.risk_score:.0f}/100"},
                        {"type": "mrkdwn", "text": f"*Tier:*\n{request.tier}"}
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Goal:* {request.original_goal}\n*Reasoning:* {' → '.join(request.reasoning_chain[:2])}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⚠️ Violations:*\n" + "\n".join(f"• {v}" for v in request.violations[:3])
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"⏰ *Expires:* {request.expires_at.strftime('%H:%M:%S')}"
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "🔗 Review Now"
                            },
                            "url": f"http://localhost:8501?request_id={request.request_id}",
                            "style": "primary"
                        }
                    ]
                }
            ]
        }
        
        try:
            response = requests.post(self.webhook_url, json=message, timeout=10)
            response.raise_for_status()
            print(f"✅ Slack notification sent for {request.request_id}")
        except Exception as e:
            print(f"⚠️ Slack notification failed: {e}")


class EmailNotifier:
    """Send HITL approvals via email"""
    
    def __init__(self, smtp_config: Optional[dict] = None):
        """
        Initialize email notifier
        
        Args:
            smtp_config: SMTP configuration dict
        """
        self.smtp_config = smtp_config or {
            'host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', 587)),
            'username': os.getenv('SMTP_USERNAME'),
            'password': os.getenv('SMTP_PASSWORD'),
            'from_email': os.getenv('SMTP_FROM_EMAIL'),
            'to_emails': os.getenv('SMTP_TO_EMAILS', '').split(',')
        }
    
    def __call__(self, request):
        """Send email notification"""
        if not all([
            self.smtp_config.get('host'),
            self.smtp_config.get('username'),
            self.smtp_config.get('password'),
            self.smtp_config.get('from_email'),
            self.smtp_config.get('to_emails')
        ]):
            return  # Missing config
        
        # Build email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 HITL Approval Required: {request.request_id}"
        msg['From'] = self.smtp_config['from_email']
        msg['To'] = ', '.join(self.smtp_config['to_emails'])
        
        # HTML body
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background: #ff4444; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f0f0f0; border-radius: 5px; }}
                .violation {{ color: #cc0000; margin: 5px 0; }}
                .button {{ background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 HITL Approval Required</h1>
                <p>Request ID: {request.request_id}</p>
            </div>
            <div class="content">
                <h2>Action Details</h2>
                <div class="metric">
                    <strong>Agent:</strong> {request.agent_id}
                </div>
                <div class="metric">
                    <strong>Tool:</strong> {request.tool_name}
                </div>
                <div class="metric">
                    <strong>Risk:</strong> {request.risk_score:.0f}/100
                </div>
                <div class="metric">
                    <strong>Tier:</strong> {request.tier}
                </div>
                
                <h3>Original Goal</h3>
                <p>{request.original_goal}</p>
                
                <h3>Reasoning Chain</h3>
                <ol>
                    {''.join(f'<li>{reason}</li>' for reason in request.reasoning_chain)}
                </ol>
                
                <h3>⚠️ Violations Detected</h3>
                {''.join(f'<p class="violation">• {v}</p>' for v in request.violations)}
                
                <h3>💡 Recommendations</h3>
                {''.join(f'<p>• {r}</p>' for r in request.recommendations)}
                
                <h3>⏰ Time Remaining</h3>
                <p>This request expires at: <strong>{request.expires_at.strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
                
                <p style="margin-top: 30px;">
                    <a href="http://localhost:8501?request_id={request.request_id}" class="button">
                        Review and Approve/Deny
                    </a>
                </p>
            </div>
        </body>
        </html>
        """
        
        # Plain text fallback
        text = f"""
        HITL Approval Required
        Request ID: {request.request_id}
        
        Agent: {request.agent_id}
        Tool: {request.tool_name}
        Risk: {request.risk_score:.0f}/100
        Tier: {request.tier}
        
        Original Goal: {request.original_goal}
        
        Reasoning:
        {chr(10).join(f'{i+1}. {r}' for i, r in enumerate(request.reasoning_chain))}
        
        Violations:
        {chr(10).join(f'• {v}' for v in request.violations)}
        
        Expires: {request.expires_at.strftime('%Y-%m-%d %H:%M:%S')}
        
        Review at: http://localhost:8501?request_id={request.request_id}
        """
        
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        try:
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            
            print(f"✅ Email notification sent for {request.request_id}")
        except Exception as e:
            print(f"⚠️ Email notification failed: {e}")


class ConsoleNotifier:
    """Simple console notification (for testing)"""
    
    def __call__(self, request):
        """Print notification to console"""
        print("\n" + "="*70)
        print("🚨 HITL APPROVAL REQUIRED")
        print("="*70)
        print(f"Request ID: {request.request_id}")
        print(f"Agent: {request.agent_id}")
        print(f"Tool: {request.tool_name}")
        print(f"Risk: {request.risk_score:.0f}/100 ({request.tier})")
        print(f"Expires: {request.expires_at.strftime('%H:%M:%S')}")
        print("\nViolations:")
        for violation in request.violations[:3]:
            print(f"  • {violation}")
        print("\nReview at: http://localhost:8501")
        print("="*70 + "\n")

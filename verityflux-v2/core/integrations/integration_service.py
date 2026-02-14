#!/usr/bin/env python3
"""
VerityFlux Enterprise - External Integrations
Real integrations with Slack, Jira, PagerDuty, Twilio, Email, and Webhooks

Features:
- Slack: Alerts, interactive approvals, channel notifications
- Jira: Ticket creation, status sync, comments
- PagerDuty: Incident escalation, on-call routing
- Twilio: SMS alerts (optional plugin)
- Email: SMTP notifications
- Webhooks: Custom HTTP integrations
- SIEM: Syslog/CEF format export
"""

import os
import json
import asyncio
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verityflux.integrations")

# HTTP client
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Slack SDK
try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    from slack_sdk.webhook import WebhookClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False

# Jira (Atlassian)
try:
    from atlassian import Jira
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False

# Twilio
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False

# Email
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# =============================================================================
# ENUMS AND CONFIGURATION
# =============================================================================

class IntegrationType(Enum):
    """Types of integrations"""
    SLACK = "slack"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    TWILIO = "twilio"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"
    TEAMS = "teams"


class NotificationPriority(Enum):
    """Notification priority levels"""
    CRITICAL = "critical"  # Immediate, all channels
    HIGH = "high"          # Urgent, primary channel + escalation
    MEDIUM = "medium"      # Standard notification
    LOW = "low"            # Batched/digest
    INFO = "info"          # Log only


class NotificationType(Enum):
    """Types of notifications"""
    ALERT = "alert"
    INCIDENT = "incident"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_RESPONSE = "approval_response"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FINDING = "scan_finding"
    SYSTEM_STATUS = "system_status"
    AGENT_STATUS = "agent_status"


@dataclass
class IntegrationConfig:
    """Base configuration for integrations"""
    integration_type: IntegrationType
    name: str
    enabled: bool = True
    
    # Notification rules
    min_priority: NotificationPriority = NotificationPriority.MEDIUM
    notification_types: List[NotificationType] = field(default_factory=list)
    
    # Rate limiting
    rate_limit_per_minute: int = 30
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None


@dataclass
class Notification:
    """Notification to be sent through integrations"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    notification_type: NotificationType = NotificationType.ALERT
    priority: NotificationPriority = NotificationPriority.MEDIUM
    
    # Content
    title: str = ""
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    organization_id: Optional[str] = None
    workspace_id: Optional[str] = None
    incident_id: Optional[str] = None
    scan_id: Optional[str] = None
    
    # Actions (for interactive notifications)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.notification_type.value,
            "priority": self.priority.value,
            "title": self.title,
            "message": self.message,
            "details": self.details,
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "incident_id": self.incident_id,
            "scan_id": self.scan_id,
            "actions": self.actions,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class IntegrationResult:
    """Result of an integration operation"""
    success: bool
    integration_type: IntegrationType
    message: str = ""
    external_id: Optional[str] = None  # ID from external system
    response_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# =============================================================================
# BASE INTEGRATION CLASS
# =============================================================================

class BaseIntegration(ABC):
    """Abstract base class for all integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self._request_count = 0
        self._last_request_time = 0
    
    @property
    @abstractmethod
    def integration_type(self) -> IntegrationType:
        pass
    
    @abstractmethod
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send a notification through this integration"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Tuple[bool, str]:
        """Test if the integration is properly configured"""
        pass
    
    async def rate_limit(self, max_per_minute: int = 30):
        """Simple rate limiting"""
        import time
        
        current_time = time.time()
        if current_time - self._last_request_time < 60:
            if self._request_count >= max_per_minute:
                wait_time = 60 - (current_time - self._last_request_time)
                await asyncio.sleep(wait_time)
                self._request_count = 0
        else:
            self._request_count = 0
        
        self._last_request_time = current_time
        self._request_count += 1


# =============================================================================
# SLACK INTEGRATION
# =============================================================================

@dataclass
class SlackConfig:
    """Slack integration configuration"""
    bot_token: str = ""
    webhook_url: str = ""
    default_channel: str = "#security-alerts"
    
    # Channel mapping by priority
    critical_channel: str = "#security-critical"
    high_channel: str = "#security-alerts"
    medium_channel: str = "#security-alerts"
    
    # Interactive features
    enable_interactive: bool = True
    signing_secret: str = ""
    
    # Appearance
    bot_name: str = "VerityFlux"
    bot_icon: str = ":shield:"


class SlackIntegration(BaseIntegration):
    """
    Slack integration for alerts and interactive approvals
    
    Features:
    - Channel notifications
    - Interactive buttons for HITL approvals
    - Thread-based conversations
    - Rich message formatting
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.bot_token = config.get("bot_token", os.getenv("SLACK_BOT_TOKEN", ""))
        self.webhook_url = config.get("webhook_url", os.getenv("SLACK_WEBHOOK_URL", ""))
        self.default_channel = config.get("default_channel", "#security-alerts")
        self.critical_channel = config.get("critical_channel", "#security-critical")
        
        # Initialize clients
        self.client = None
        self.webhook_client = None
        
        if SLACK_AVAILABLE:
            if self.bot_token:
                self.client = WebClient(token=self.bot_token)
            if self.webhook_url:
                self.webhook_client = WebhookClient(self.webhook_url)
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.SLACK
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send notification to Slack"""
        if not self.enabled:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Integration disabled"
            )
        
        await self.rate_limit()
        
        try:
            # Build Slack message
            blocks = self._build_message_blocks(notification)
            channel = self._get_channel_for_priority(notification.priority)
            
            # Send via bot API or webhook
            if self.client:
                response = self.client.chat_postMessage(
                    channel=channel,
                    text=notification.title,
                    blocks=blocks,
                    unfurl_links=False,
                )
                
                return IntegrationResult(
                    success=True,
                    integration_type=self.integration_type,
                    message=f"Message sent to {channel}",
                    external_id=response.get("ts"),
                    response_data={"channel": channel, "ts": response.get("ts")}
                )
            
            elif self.webhook_client:
                response = self.webhook_client.send(
                    text=notification.title,
                    blocks=blocks
                )
                
                return IntegrationResult(
                    success=response.status_code == 200,
                    integration_type=self.integration_type,
                    message="Message sent via webhook"
                )
            
            else:
                return IntegrationResult(
                    success=False,
                    integration_type=self.integration_type,
                    error="No Slack client configured"
                )
                
        except SlackApiError as e:
            logger.error(f"Slack API error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
        except Exception as e:
            logger.error(f"Slack error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    def _build_message_blocks(self, notification: Notification) -> List[Dict]:
        """Build Slack Block Kit message"""
        blocks = []
        
        # Header with emoji based on priority
        priority_emoji = {
            NotificationPriority.CRITICAL: "🚨",
            NotificationPriority.HIGH: "⚠️",
            NotificationPriority.MEDIUM: "📢",
            NotificationPriority.LOW: "ℹ️",
            NotificationPriority.INFO: "📝",
        }
        
        emoji = priority_emoji.get(notification.priority, "📢")
        
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {notification.title}",
                "emoji": True
            }
        })
        
        # Main message
        if notification.message:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": notification.message
                }
            })
        
        # Details as fields
        if notification.details:
            fields = []
            for key, value in list(notification.details.items())[:10]:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*{key}:*\n{value}"
                })
            
            # Split into sections of 2 fields each
            for i in range(0, len(fields), 2):
                blocks.append({
                    "type": "section",
                    "fields": fields[i:i+2]
                })
        
        # Actions (buttons)
        if notification.actions:
            action_elements = []
            for action in notification.actions[:5]:
                style = "danger" if action.get("style") == "danger" else "primary"
                action_elements.append({
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": action.get("label", "Action"),
                        "emoji": True
                    },
                    "value": json.dumps({
                        "notification_id": notification.id,
                        "action_id": action.get("id"),
                        "action_type": action.get("type"),
                    }),
                    "action_id": action.get("id", str(uuid.uuid4())),
                    "style": style
                })
            
            blocks.append({
                "type": "actions",
                "elements": action_elements
            })
        
        # Footer with timestamp
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"⏰ {notification.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} | 🔒 VerityFlux Security"
                }
            ]
        })
        
        return blocks
    
    def _get_channel_for_priority(self, priority: NotificationPriority) -> str:
        """Get appropriate channel based on priority"""
        if priority == NotificationPriority.CRITICAL:
            return self.critical_channel
        return self.default_channel
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test Slack connection"""
        if not SLACK_AVAILABLE:
            return False, "Slack SDK not installed"
        
        if self.client:
            try:
                response = self.client.auth_test()
                return True, f"Connected as {response.get('user', 'unknown')}"
            except SlackApiError as e:
                return False, f"Auth failed: {e}"
        
        if self.webhook_client:
            return True, "Webhook configured (cannot test without sending)"
        
        return False, "No Slack credentials configured"
    
    async def send_approval_request(
        self,
        approval_id: str,
        title: str,
        description: str,
        risk_score: float,
        details: Dict[str, Any],
        channel: str = None
    ) -> IntegrationResult:
        """Send an interactive approval request"""
        notification = Notification(
            id=approval_id,
            notification_type=NotificationType.APPROVAL_REQUEST,
            priority=NotificationPriority.HIGH if risk_score > 70 else NotificationPriority.MEDIUM,
            title=f"🔐 Approval Required: {title}",
            message=description,
            details={
                "Risk Score": f"{risk_score:.0f}/100",
                **details
            },
            actions=[
                {"id": f"approve_{approval_id}", "label": "✅ Approve", "type": "approve", "style": "primary"},
                {"id": f"deny_{approval_id}", "label": "❌ Deny", "type": "deny", "style": "danger"},
                {"id": f"investigate_{approval_id}", "label": "🔍 Investigate", "type": "investigate"},
            ]
        )
        
        return await self.send_notification(notification)


# =============================================================================
# JIRA INTEGRATION
# =============================================================================

@dataclass
class JiraConfig:
    """Jira integration configuration"""
    url: str = ""
    username: str = ""
    api_token: str = ""
    project_key: str = "SEC"
    
    # Issue type mapping
    incident_type: str = "Bug"
    vulnerability_type: str = "Security"
    task_type: str = "Task"
    
    # Field mappings
    priority_mapping: Dict[str, str] = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    })
    
    # Labels
    default_labels: List[str] = field(default_factory=lambda: ["verityflux", "security"])


class JiraIntegration(BaseIntegration):
    """
    Jira integration for ticket management
    
    Features:
    - Create security incidents as tickets
    - Sync scan findings to issues
    - Update ticket status
    - Add comments and attachments
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.url = config.get("url", os.getenv("JIRA_URL", ""))
        self.username = config.get("username", os.getenv("JIRA_USERNAME", ""))
        self.api_token = config.get("api_token", os.getenv("JIRA_API_TOKEN", ""))
        self.project_key = config.get("project_key", "SEC")
        
        self.priority_mapping = config.get("priority_mapping", {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        })
        
        self.default_labels = config.get("default_labels", ["verityflux", "security"])
        
        # Initialize client
        self.client = None
        if JIRA_AVAILABLE and self.url and self.username and self.api_token:
            try:
                self.client = Jira(
                    url=self.url,
                    username=self.username,
                    password=self.api_token
                )
            except Exception as e:
                logger.error(f"Failed to initialize Jira client: {e}")
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.JIRA
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Create a Jira ticket from notification"""
        if not self.enabled or not self.client:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Jira integration not configured"
            )
        
        await self.rate_limit(max_per_minute=60)
        
        try:
            # Determine issue type
            if notification.notification_type == NotificationType.INCIDENT:
                issue_type = "Bug"
            elif notification.notification_type == NotificationType.SCAN_FINDING:
                issue_type = "Task"
            else:
                issue_type = "Task"
            
            # Build description
            description = self._build_description(notification)
            
            # Map priority
            priority_name = self.priority_mapping.get(
                notification.priority.value, "Medium"
            )
            
            # Create issue
            issue_data = {
                "project": {"key": self.project_key},
                "summary": notification.title[:255],
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_name},
                "labels": self.default_labels + [notification.notification_type.value],
            }
            
            # Add custom fields if present
            if notification.incident_id:
                issue_data["description"] += f"\n\nIncident ID: {notification.incident_id}"
            if notification.scan_id:
                issue_data["description"] += f"\nScan ID: {notification.scan_id}"
            
            # Create the issue
            issue = self.client.issue_create(fields=issue_data)
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Created Jira issue {issue.get('key')}",
                external_id=issue.get("key"),
                response_data=issue
            )
            
        except Exception as e:
            logger.error(f"Jira error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    def _build_description(self, notification: Notification) -> str:
        """Build Jira description with formatting"""
        lines = [
            f"h2. {notification.title}",
            "",
            notification.message,
            "",
            "h3. Details",
            "||Field||Value||",
        ]
        
        for key, value in notification.details.items():
            lines.append(f"|{key}|{value}|")
        
        lines.extend([
            "",
            f"_Generated by VerityFlux at {notification.timestamp.isoformat()}_"
        ])
        
        return "\n".join(lines)
    
    async def create_incident_ticket(
        self,
        incident_id: str,
        title: str,
        description: str,
        priority: str,
        details: Dict[str, Any]
    ) -> IntegrationResult:
        """Create a ticket for a security incident"""
        notification = Notification(
            notification_type=NotificationType.INCIDENT,
            priority=NotificationPriority[priority.upper()],
            title=f"[INCIDENT] {title}",
            message=description,
            details=details,
            incident_id=incident_id,
        )
        return await self.send_notification(notification)
    
    async def create_finding_ticket(
        self,
        finding_id: str,
        vuln_id: str,
        title: str,
        severity: str,
        description: str,
        recommendation: str,
        scan_id: str = None
    ) -> IntegrationResult:
        """Create a ticket for a scan finding"""
        notification = Notification(
            notification_type=NotificationType.SCAN_FINDING,
            priority=NotificationPriority[severity.upper()],
            title=f"[{vuln_id}] {title}",
            message=description,
            details={
                "Vulnerability ID": vuln_id,
                "Severity": severity,
                "Recommendation": recommendation[:200],
            },
            scan_id=scan_id,
        )
        return await self.send_notification(notification)
    
    async def update_ticket(
        self,
        issue_key: str,
        status: str = None,
        comment: str = None,
        resolution: str = None
    ) -> IntegrationResult:
        """Update an existing Jira ticket"""
        if not self.client:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Jira client not available"
            )
        
        try:
            # Add comment
            if comment:
                self.client.issue_add_comment(issue_key, comment)
            
            # Transition status
            if status:
                transitions = self.client.get_issue_transitions(issue_key)
                for t in transitions:
                    if t["name"].lower() == status.lower():
                        self.client.issue_transition(issue_key, t["id"])
                        break
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Updated {issue_key}",
                external_id=issue_key
            )
            
        except Exception as e:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test Jira connection"""
        if not JIRA_AVAILABLE:
            return False, "Jira library not installed (pip install atlassian-python-api)"
        
        if not self.client:
            return False, "Jira client not configured"
        
        try:
            # Try to get project info
            project = self.client.project(self.project_key)
            return True, f"Connected to project: {project.get('name', self.project_key)}"
        except Exception as e:
            return False, f"Connection failed: {e}"


# =============================================================================
# PAGERDUTY INTEGRATION
# =============================================================================

@dataclass
class PagerDutyConfig:
    """PagerDuty integration configuration"""
    api_key: str = ""
    routing_key: str = ""  # Events API v2 routing key
    service_id: str = ""
    
    # Severity mapping
    severity_mapping: Dict[str, str] = field(default_factory=lambda: {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
    })


class PagerDutyIntegration(BaseIntegration):
    """
    PagerDuty integration for incident escalation
    
    Features:
    - Create incidents
    - Trigger alerts
    - Acknowledge/resolve incidents
    - On-call routing
    """
    
    EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.api_key = config.get("api_key", os.getenv("PAGERDUTY_API_KEY", ""))
        self.routing_key = config.get("routing_key", os.getenv("PAGERDUTY_ROUTING_KEY", ""))
        self.service_id = config.get("service_id", "")
        
        self.severity_mapping = config.get("severity_mapping", {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        })
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.PAGERDUTY
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send alert to PagerDuty"""
        if not self.enabled or not self.routing_key:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="PagerDuty not configured"
            )
        
        if not HTTPX_AVAILABLE:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="httpx not available"
            )
        
        await self.rate_limit()
        
        try:
            # Map severity
            severity = self.severity_mapping.get(
                notification.priority.value, "warning"
            )
            
            # Build event payload
            payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "dedup_key": notification.id,
                "payload": {
                    "summary": notification.title,
                    "severity": severity,
                    "source": "VerityFlux",
                    "component": notification.details.get("component", "security"),
                    "group": notification.notification_type.value,
                    "class": "security-alert",
                    "custom_details": {
                        "message": notification.message,
                        "notification_type": notification.notification_type.value,
                        "priority": notification.priority.value,
                        **notification.details
                    }
                },
                "links": [],
                "images": []
            }
            
            # Add context links
            if notification.incident_id:
                payload["links"].append({
                    "href": f"https://verityflux.ai/incidents/{notification.incident_id}",
                    "text": "View in VerityFlux"
                })
            
            # Send to PagerDuty Events API
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                data = response.json()
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Alert sent to PagerDuty",
                external_id=data.get("dedup_key"),
                response_data=data
            )
            
        except Exception as e:
            logger.error(f"PagerDuty error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    async def resolve_incident(self, dedup_key: str) -> IntegrationResult:
        """Resolve a PagerDuty incident"""
        if not HTTPX_AVAILABLE or not self.routing_key:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Not configured"
            )
        
        try:
            payload = {
                "routing_key": self.routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload
                )
                response.raise_for_status()
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message="Incident resolved"
            )
            
        except Exception as e:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    async def acknowledge_incident(self, dedup_key: str) -> IntegrationResult:
        """Acknowledge a PagerDuty incident"""
        if not HTTPX_AVAILABLE or not self.routing_key:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Not configured"
            )
        
        try:
            payload = {
                "routing_key": self.routing_key,
                "event_action": "acknowledge",
                "dedup_key": dedup_key
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.EVENTS_API_URL,
                    json=payload
                )
                response.raise_for_status()
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message="Incident acknowledged"
            )
            
        except Exception as e:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test PagerDuty connection"""
        if not HTTPX_AVAILABLE:
            return False, "httpx not available"
        
        if not self.routing_key:
            return False, "Routing key not configured"
        
        # We can't fully test without triggering an alert
        # Just verify the routing key format
        if len(self.routing_key) >= 32:
            return True, "Routing key configured (format valid)"
        
        return False, "Invalid routing key format"


# =============================================================================
# TWILIO INTEGRATION (SMS)
# =============================================================================

@dataclass
class TwilioConfig:
    """Twilio configuration for SMS alerts"""
    account_sid: str = ""
    auth_token: str = ""
    from_number: str = ""
    to_numbers: List[str] = field(default_factory=list)
    
    # Only for critical alerts by default
    min_priority: NotificationPriority = NotificationPriority.CRITICAL


class TwilioIntegration(BaseIntegration):
    """
    Twilio integration for SMS alerts
    
    Features:
    - SMS notifications for critical alerts
    - Multiple recipient support
    - Rate limiting to prevent spam
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.account_sid = config.get("account_sid", os.getenv("TWILIO_ACCOUNT_SID", ""))
        self.auth_token = config.get("auth_token", os.getenv("TWILIO_AUTH_TOKEN", ""))
        self.from_number = config.get("from_number", os.getenv("TWILIO_FROM_NUMBER", ""))
        self.to_numbers = config.get("to_numbers", [])
        self.min_priority = NotificationPriority(
            config.get("min_priority", "critical")
        )
        
        # Initialize client
        self.client = None
        if TWILIO_AVAILABLE and self.account_sid and self.auth_token:
            self.client = TwilioClient(self.account_sid, self.auth_token)
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.TWILIO
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send SMS notification"""
        if not self.enabled or not self.client:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Twilio not configured"
            )
        
        # Check priority threshold
        priority_order = [p.value for p in NotificationPriority]
        if priority_order.index(notification.priority.value) > priority_order.index(self.min_priority.value):
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message="Skipped: Below priority threshold"
            )
        
        if not self.to_numbers:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="No recipient numbers configured"
            )
        
        await self.rate_limit(max_per_minute=10)  # SMS rate limit
        
        try:
            # Build SMS message (160 char limit for single SMS)
            message = f"🚨 {notification.title[:100]}\n{notification.message[:50]}"
            
            results = []
            for to_number in self.to_numbers:
                sms = self.client.messages.create(
                    body=message,
                    from_=self.from_number,
                    to=to_number
                )
                results.append(sms.sid)
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Sent to {len(results)} numbers",
                response_data={"message_sids": results}
            )
            
        except Exception as e:
            logger.error(f"Twilio error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test Twilio connection"""
        if not TWILIO_AVAILABLE:
            return False, "Twilio SDK not installed (pip install twilio)"
        
        if not self.client:
            return False, "Twilio client not configured"
        
        try:
            # Verify account
            account = self.client.api.accounts(self.account_sid).fetch()
            return True, f"Connected: {account.friendly_name}"
        except Exception as e:
            return False, f"Connection failed: {e}"


# =============================================================================
# EMAIL INTEGRATION
# =============================================================================

@dataclass
class EmailConfig:
    """Email integration configuration"""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    
    from_address: str = ""
    from_name: str = "VerityFlux Security"
    
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)


class EmailIntegration(BaseIntegration):
    """
    Email integration for notifications
    
    Features:
    - SMTP email sending
    - HTML and plain text formatting
    - Multiple recipients
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.smtp_host = config.get("smtp_host", os.getenv("SMTP_HOST", ""))
        self.smtp_port = config.get("smtp_port", int(os.getenv("SMTP_PORT", "587")))
        self.smtp_user = config.get("smtp_user", os.getenv("SMTP_USER", ""))
        self.smtp_password = config.get("smtp_password", os.getenv("SMTP_PASSWORD", ""))
        self.use_tls = config.get("use_tls", True)
        
        self.from_address = config.get("from_address", os.getenv("EMAIL_FROM", ""))
        self.from_name = config.get("from_name", "VerityFlux Security")
        self.to_addresses = config.get("to_addresses", [])
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.EMAIL
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send email notification"""
        if not self.enabled:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Email integration disabled"
            )
        
        if not self.smtp_host or not self.to_addresses:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Email not configured"
            )
        
        await self.rate_limit()
        
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{notification.priority.value.upper()}] {notification.title}"
            msg["From"] = f"{self.from_name} <{self.from_address}>"
            msg["To"] = ", ".join(self.to_addresses)
            
            # Plain text version
            text_content = self._build_text_email(notification)
            msg.attach(MIMEText(text_content, "plain"))
            
            # HTML version
            html_content = self._build_html_email(notification)
            msg.attach(MIMEText(html_content, "html"))
            
            # Send email
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp, msg)
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Email sent to {len(self.to_addresses)} recipients"
            )
            
        except Exception as e:
            logger.error(f"Email error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    def _send_smtp(self, msg: MIMEMultipart):
        """Send email via SMTP (blocking)"""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            if self.use_tls:
                server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
    
    def _build_text_email(self, notification: Notification) -> str:
        """Build plain text email"""
        lines = [
            f"{'=' * 50}",
            f"VERITYFLUX SECURITY ALERT",
            f"{'=' * 50}",
            f"",
            f"Priority: {notification.priority.value.upper()}",
            f"Type: {notification.notification_type.value}",
            f"Time: {notification.timestamp.isoformat()}",
            f"",
            f"{'-' * 50}",
            f"",
            f"{notification.title}",
            f"",
            f"{notification.message}",
            f"",
        ]
        
        if notification.details:
            lines.append(f"{'-' * 50}")
            lines.append("Details:")
            for key, value in notification.details.items():
                lines.append(f"  {key}: {value}")
        
        lines.extend([
            f"",
            f"{'-' * 50}",
            f"This is an automated message from VerityFlux.",
        ])
        
        return "\n".join(lines)
    
    def _build_html_email(self, notification: Notification) -> str:
        """Build HTML email"""
        priority_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        
        color = priority_colors.get(notification.priority.value, "#6c757d")
        
        details_html = ""
        if notification.details:
            details_rows = "".join([
                f"<tr><td style='padding: 8px; border-bottom: 1px solid #ddd;'><strong>{k}</strong></td>"
                f"<td style='padding: 8px; border-bottom: 1px solid #ddd;'>{v}</td></tr>"
                for k, v in notification.details.items()
            ])
            details_html = f"""
            <h3 style="color: #333; margin-top: 20px;">Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
                {details_rows}
            </table>
            """
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: {color}; color: white; padding: 15px; border-radius: 5px 5px 0 0;">
                    <h1 style="margin: 0; font-size: 18px;">
                        🔒 VerityFlux Security Alert
                    </h1>
                    <p style="margin: 5px 0 0 0; font-size: 14px;">
                        Priority: {notification.priority.value.upper()}
                    </p>
                </div>
                
                <div style="background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-top: none;">
                    <h2 style="color: #333; margin-top: 0;">{notification.title}</h2>
                    <p>{notification.message}</p>
                    
                    {details_html}
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    
                    <p style="color: #666; font-size: 12px;">
                        Type: {notification.notification_type.value}<br>
                        Time: {notification.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                        ID: {notification.id}
                    </p>
                </div>
                
                <div style="text-align: center; padding: 15px; color: #666; font-size: 12px;">
                    This is an automated message from VerityFlux Security Platform.
                </div>
            </div>
        </body>
        </html>
        """
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test email connection"""
        if not self.smtp_host:
            return False, "SMTP host not configured"
        
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                return True, f"Connected to {self.smtp_host}:{self.smtp_port}"
        except Exception as e:
            return False, f"Connection failed: {e}"


# =============================================================================
# WEBHOOK INTEGRATION
# =============================================================================

@dataclass
class WebhookConfig:
    """Webhook integration configuration"""
    url: str = ""
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Authentication
    auth_type: str = "none"  # none, bearer, basic, hmac
    auth_token: str = ""
    auth_secret: str = ""
    
    # Payload
    payload_template: Optional[Dict] = None


class WebhookIntegration(BaseIntegration):
    """
    Generic webhook integration for custom HTTP endpoints
    
    Features:
    - Configurable HTTP method and headers
    - Multiple auth types (Bearer, Basic, HMAC)
    - Custom payload templates
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.url = config.get("url", "")
        self.method = config.get("method", "POST").upper()
        self.headers = config.get("headers", {})
        
        self.auth_type = config.get("auth_type", "none")
        self.auth_token = config.get("auth_token", "")
        self.auth_secret = config.get("auth_secret", "")
        
        self.payload_template = config.get("payload_template")
    
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.WEBHOOK
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send webhook notification"""
        if not self.enabled or not self.url:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="Webhook not configured"
            )
        
        if not HTTPX_AVAILABLE:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="httpx not available"
            )
        
        await self.rate_limit()
        
        try:
            # Build payload
            if self.payload_template:
                payload = self._apply_template(self.payload_template, notification)
            else:
                payload = notification.to_dict()
            
            # Build headers
            headers = {
                "Content-Type": "application/json",
                **self.headers
            }
            
            # Apply authentication
            if self.auth_type == "bearer" and self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            elif self.auth_type == "hmac" and self.auth_secret:
                signature = hmac.new(
                    self.auth_secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-Signature"] = signature
            
            # Send request
            async with httpx.AsyncClient() as client:
                if self.method == "POST":
                    response = await client.post(self.url, json=payload, headers=headers)
                elif self.method == "PUT":
                    response = await client.put(self.url, json=payload, headers=headers)
                else:
                    response = await client.post(self.url, json=payload, headers=headers)
                
                response.raise_for_status()
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message=f"Webhook sent ({response.status_code})",
                response_data={"status_code": response.status_code}
            )
            
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    def _apply_template(self, template: Dict, notification: Notification) -> Dict:
        """Apply notification data to template"""
        result = {}
        notification_dict = notification.to_dict()
        
        for key, value in template.items():
            if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
                # Template variable
                var_name = value[2:-2].strip()
                result[key] = notification_dict.get(var_name, value)
            elif isinstance(value, dict):
                result[key] = self._apply_template(value, notification)
            else:
                result[key] = value
        
        return result
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test webhook endpoint"""
        if not HTTPX_AVAILABLE:
            return False, "httpx not available"
        
        if not self.url:
            return False, "Webhook URL not configured"
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.options(self.url, timeout=10)
                return True, f"Endpoint reachable ({response.status_code})"
        except Exception as e:
            return False, f"Connection failed: {e}"


# =============================================================================
# SIEM INTEGRATION
# =============================================================================

class SIEMIntegration(BaseIntegration):
    """
    SIEM integration for security event logging
    
    Features:
    - Syslog format (RFC 5424)
    - CEF (Common Event Format)
    - JSON format
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.siem_url = config.get("url", "")
        self.format = config.get("format", "cef")  # cef, syslog, json
        self.facility = config.get("facility", 1)  # user-level
        
    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.SIEM
    
    async def send_notification(self, notification: Notification) -> IntegrationResult:
        """Send event to SIEM"""
        if not self.enabled or not self.siem_url:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error="SIEM not configured"
            )
        
        try:
            if self.format == "cef":
                payload = self._to_cef(notification)
            elif self.format == "syslog":
                payload = self._to_syslog(notification)
            else:
                payload = notification.to_dict()
            
            # Send to SIEM
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.siem_url,
                    json=payload if isinstance(payload, dict) else {"message": payload}
                )
                response.raise_for_status()
            
            return IntegrationResult(
                success=True,
                integration_type=self.integration_type,
                message="Event sent to SIEM"
            )
            
        except Exception as e:
            return IntegrationResult(
                success=False,
                integration_type=self.integration_type,
                error=str(e)
            )
    
    def _to_cef(self, notification: Notification) -> str:
        """Convert to CEF format"""
        severity_map = {
            "critical": 10,
            "high": 7,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        
        severity = severity_map.get(notification.priority.value, 5)
        
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef = f"CEF:0|VerityFlux|SecurityPlatform|3.5|{notification.notification_type.value}|{notification.title}|{severity}|"
        
        # Add extension fields
        extensions = [
            f"msg={notification.message[:200]}",
            f"src=VerityFlux",
            f"rt={int(notification.timestamp.timestamp() * 1000)}",
        ]
        
        for key, value in list(notification.details.items())[:5]:
            safe_key = key.replace(" ", "_")[:23]
            safe_value = str(value).replace("=", "\\=")[:100]
            extensions.append(f"cs1Label={safe_key} cs1={safe_value}")
        
        return cef + " ".join(extensions)
    
    def _to_syslog(self, notification: Notification) -> str:
        """Convert to Syslog format (RFC 5424)"""
        severity_map = {
            "critical": 2,  # Critical
            "high": 3,      # Error
            "medium": 4,    # Warning
            "low": 5,       # Notice
            "info": 6,      # Informational
        }
        
        severity = severity_map.get(notification.priority.value, 5)
        priority = (self.facility * 8) + severity
        
        timestamp = notification.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        return f"<{priority}>1 {timestamp} verityflux security - - - {notification.title}: {notification.message}"
    
    async def test_connection(self) -> Tuple[bool, str]:
        """Test SIEM connection"""
        if not self.siem_url:
            return False, "SIEM URL not configured"
        
        return True, "SIEM configured (format: {})".format(self.format)


# =============================================================================
# INTEGRATION MANAGER
# =============================================================================

class IntegrationManager:
    """
    Centralized manager for all integrations
    
    Features:
    - Register and manage integrations
    - Route notifications to appropriate integrations
    - Handle failures and retries
    """
    
    def __init__(self):
        self.integrations: Dict[str, BaseIntegration] = {}
        self._notification_rules: List[Dict[str, Any]] = []
    
    def register_integration(
        self,
        name: str,
        integration_type: IntegrationType,
        config: Dict[str, Any]
    ) -> BaseIntegration:
        """Register a new integration"""
        
        integration_classes = {
            IntegrationType.SLACK: SlackIntegration,
            IntegrationType.JIRA: JiraIntegration,
            IntegrationType.PAGERDUTY: PagerDutyIntegration,
            IntegrationType.TWILIO: TwilioIntegration,
            IntegrationType.EMAIL: EmailIntegration,
            IntegrationType.WEBHOOK: WebhookIntegration,
            IntegrationType.SIEM: SIEMIntegration,
        }
        
        integration_class = integration_classes.get(integration_type)
        if not integration_class:
            raise ValueError(f"Unknown integration type: {integration_type}")
        
        integration = integration_class(config)
        self.integrations[name] = integration
        
        logger.info(f"Registered integration: {name} ({integration_type.value})")
        return integration
    
    def get_integration(self, name: str) -> Optional[BaseIntegration]:
        """Get an integration by name"""
        return self.integrations.get(name)
    
    def add_notification_rule(
        self,
        integration_name: str,
        notification_types: List[NotificationType] = None,
        min_priority: NotificationPriority = NotificationPriority.MEDIUM,
        conditions: Dict[str, Any] = None
    ):
        """Add a rule for routing notifications"""
        self._notification_rules.append({
            "integration": integration_name,
            "types": notification_types or list(NotificationType),
            "min_priority": min_priority,
            "conditions": conditions or {},
        })
    
    async def send_notification(
        self,
        notification: Notification,
        integrations: List[str] = None
    ) -> Dict[str, IntegrationResult]:
        """
        Send notification to all matching integrations
        
        Args:
            notification: The notification to send
            integrations: Specific integrations to use (or None for all matching)
            
        Returns:
            Dict of integration name -> result
        """
        results = {}
        
        # Determine target integrations
        if integrations:
            targets = [
                (name, self.integrations[name])
                for name in integrations
                if name in self.integrations
            ]
        else:
            targets = self._get_matching_integrations(notification)
        
        # Send to all targets
        for name, integration in targets:
            try:
                result = await integration.send_notification(notification)
                results[name] = result
            except Exception as e:
                logger.error(f"Integration {name} failed: {e}")
                results[name] = IntegrationResult(
                    success=False,
                    integration_type=integration.integration_type,
                    error=str(e)
                )
        
        return results
    
    def _get_matching_integrations(
        self,
        notification: Notification
    ) -> List[Tuple[str, BaseIntegration]]:
        """Get integrations that match notification rules"""
        matches = []
        priority_order = [p.value for p in NotificationPriority]
        
        for rule in self._notification_rules:
            integration_name = rule["integration"]
            integration = self.integrations.get(integration_name)
            
            if not integration or not integration.enabled:
                continue
            
            # Check notification type
            if notification.notification_type not in rule["types"]:
                continue
            
            # Check priority
            notification_priority_idx = priority_order.index(notification.priority.value)
            rule_priority_idx = priority_order.index(rule["min_priority"].value)
            
            if notification_priority_idx > rule_priority_idx:
                continue
            
            # Check custom conditions
            conditions_met = True
            for key, value in rule.get("conditions", {}).items():
                if notification.details.get(key) != value:
                    conditions_met = False
                    break
            
            if conditions_met:
                matches.append((integration_name, integration))
        
        return matches
    
    async def test_all_connections(self) -> Dict[str, Tuple[bool, str]]:
        """Test all registered integrations"""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                success, message = await integration.test_connection()
                results[name] = (success, message)
            except Exception as e:
                results[name] = (False, str(e))
        
        return results
    
    def list_integrations(self) -> List[Dict[str, Any]]:
        """List all registered integrations"""
        return [
            {
                "name": name,
                "type": integration.integration_type.value,
                "enabled": integration.enabled,
            }
            for name, integration in self.integrations.items()
        ]


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_integration_manager_from_config(config: Dict[str, Any]) -> IntegrationManager:
    """Create IntegrationManager from configuration dict"""
    manager = IntegrationManager()
    
    for int_config in config.get("integrations", []):
        name = int_config.get("name")
        int_type = IntegrationType(int_config.get("type"))
        manager.register_integration(name, int_type, int_config)
    
    for rule in config.get("notification_rules", []):
        manager.add_notification_rule(
            integration_name=rule.get("integration"),
            notification_types=[NotificationType(t) for t in rule.get("types", [])],
            min_priority=NotificationPriority(rule.get("min_priority", "medium")),
            conditions=rule.get("conditions", {}),
        )
    
    return manager


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    async def test_integrations():
        print("=" * 60)
        print("Testing Integrations Module")
        print("=" * 60)
        
        # Create manager
        manager = IntegrationManager()
        
        # Register integrations (with mock configs)
        print("\n📡 Registering integrations...")
        
        # Slack (mock)
        manager.register_integration("slack", IntegrationType.SLACK, {
            "webhook_url": "https://hooks.slack.com/services/xxx",
            "default_channel": "#security-alerts",
        })
        
        # Email (mock)
        manager.register_integration("email", IntegrationType.EMAIL, {
            "smtp_host": "smtp.example.com",
            "from_address": "security@example.com",
            "to_addresses": ["admin@example.com"],
        })
        
        # Webhook (mock)
        manager.register_integration("custom_webhook", IntegrationType.WEBHOOK, {
            "url": "https://api.example.com/webhooks/security",
            "auth_type": "bearer",
            "auth_token": "test-token",
        })
        
        # PagerDuty (mock)
        manager.register_integration("pagerduty", IntegrationType.PAGERDUTY, {
            "routing_key": "test-routing-key-1234567890123456789012",
        })
        
        # Add notification rules
        print("\n📋 Adding notification rules...")
        
        manager.add_notification_rule(
            "slack",
            notification_types=[NotificationType.ALERT, NotificationType.INCIDENT],
            min_priority=NotificationPriority.MEDIUM,
        )
        
        manager.add_notification_rule(
            "pagerduty",
            notification_types=[NotificationType.INCIDENT],
            min_priority=NotificationPriority.HIGH,
        )
        
        manager.add_notification_rule(
            "email",
            notification_types=list(NotificationType),
            min_priority=NotificationPriority.LOW,
        )
        
        # List integrations
        print("\n📊 Registered integrations:")
        for info in manager.list_integrations():
            print(f"  - {info['name']}: {info['type']} (enabled: {info['enabled']})")
        
        # Create test notification
        print("\n📨 Creating test notification...")
        notification = Notification(
            notification_type=NotificationType.ALERT,
            priority=NotificationPriority.HIGH,
            title="Critical Security Alert: Prompt Injection Detected",
            message="An AI agent attempted to execute a prompt injection attack.",
            details={
                "Agent": "customer-service-bot",
                "Risk Score": "92/100",
                "Vulnerability": "LLM01",
                "Action Taken": "Blocked",
            },
            actions=[
                {"id": "approve", "label": "Approve", "type": "approve"},
                {"id": "investigate", "label": "Investigate", "type": "investigate"},
            ]
        )
        
        print(f"  Title: {notification.title}")
        print(f"  Priority: {notification.priority.value}")
        print(f"  Type: {notification.notification_type.value}")
        
        # Test connections
        print("\n🔌 Testing connections...")
        connection_results = await manager.test_all_connections()
        for name, (success, message) in connection_results.items():
            status = "✅" if success else "❌"
            print(f"  {status} {name}: {message}")
        
        # Test Slack message building
        print("\n🎨 Testing Slack message formatting...")
        slack_integration = manager.get_integration("slack")
        if isinstance(slack_integration, SlackIntegration):
            blocks = slack_integration._build_message_blocks(notification)
            print(f"  Generated {len(blocks)} Slack blocks")
        
        # Test Email formatting
        print("\n📧 Testing Email formatting...")
        email_integration = manager.get_integration("email")
        if isinstance(email_integration, EmailIntegration):
            text = email_integration._build_text_email(notification)
            html = email_integration._build_html_email(notification)
            print(f"  Text email: {len(text)} chars")
            print(f"  HTML email: {len(html)} chars")
        
        # Test SIEM formatting
        print("\n📊 Testing SIEM formatting...")
        siem = SIEMIntegration({"url": "http://siem.example.com", "format": "cef"})
        cef = siem._to_cef(notification)
        syslog = siem._to_syslog(notification)
        print(f"  CEF: {cef[:100]}...")
        print(f"  Syslog: {syslog[:100]}...")
        
        print("\n✅ Integration tests complete!")
    
    asyncio.run(test_integrations())

#!/usr/bin/env python3
"""
VerityFlux Enterprise - SOC Command Center
Comprehensive Security Operations Center for AI Agent Security

Features:
- Real-time security event monitoring
- Incident management (create, assign, track, resolve)
- Agent health monitoring and inventory
- Playbook automation
- Dashboard metrics and analytics
- Alert correlation and deduplication
- On-call scheduling integration
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import uuid
import hashlib

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verityflux.soc")

# For async operations
try:
    import asyncio
    from asyncio import Queue
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False


# =============================================================================
# ENUMS
# =============================================================================

class IncidentStatus(Enum):
    """Incident lifecycle status"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentPriority(Enum):
    """Incident priority levels with SLA"""
    P1_CRITICAL = "p1_critical"    # Response: 15 min, Resolve: 4 hours
    P2_HIGH = "p2_high"            # Response: 1 hour, Resolve: 24 hours
    P3_MEDIUM = "p3_medium"        # Response: 4 hours, Resolve: 72 hours
    P4_LOW = "p4_low"              # Response: 24 hours, Resolve: 1 week


class IncidentType(Enum):
    """Types of security incidents"""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOOL_MISUSE = "tool_misuse"
    GOAL_HIJACKING = "goal_hijacking"
    BACKDOOR_DETECTED = "backdoor_detected"
    ROGUE_AGENT = "rogue_agent"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SYSTEM_COMPROMISE = "system_compromise"
    OTHER = "other"


class AgentStatus(Enum):
    """Monitored agent status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    SUSPENDED = "suspended"


class EventSeverity(Enum):
    """Security event severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


# =============================================================================
# SLA CONFIGURATION
# =============================================================================

SLA_CONFIG = {
    IncidentPriority.P1_CRITICAL: {
        "response_time_minutes": 15,
        "resolution_time_hours": 4,
        "escalation_after_minutes": 10,
        "notification_channels": ["slack", "pagerduty", "sms", "email"],
    },
    IncidentPriority.P2_HIGH: {
        "response_time_minutes": 60,
        "resolution_time_hours": 24,
        "escalation_after_minutes": 45,
        "notification_channels": ["slack", "pagerduty", "email"],
    },
    IncidentPriority.P3_MEDIUM: {
        "response_time_minutes": 240,
        "resolution_time_hours": 72,
        "escalation_after_minutes": 180,
        "notification_channels": ["slack", "email"],
    },
    IncidentPriority.P4_LOW: {
        "response_time_minutes": 1440,
        "resolution_time_hours": 168,
        "escalation_after_minutes": 720,
        "notification_channels": ["email"],
    },
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SecurityEvent:
    """Real-time security event from agents"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Source
    organization_id: str = ""
    workspace_id: str = ""
    agent_id: str = ""
    agent_name: str = ""
    
    # Event details
    event_type: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    
    # Action context
    tool_name: str = ""
    action_parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning_chain: List[str] = field(default_factory=list)
    original_goal: str = ""
    
    # Decision
    decision: str = ""  # allow, block, require_approval
    risk_score: float = 0.0
    confidence: float = 0.0
    
    # Analysis
    violations: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    
    # Context
    session_id: str = ""
    request_id: str = ""
    source_ip: str = ""
    user_id: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "tool_name": self.tool_name,
            "action_parameters": self.action_parameters,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "violations": self.violations,
        }


@dataclass
class Alert:
    """Security alert (aggregated from events)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Alert details
    title: str = ""
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    
    # Source
    organization_id: str = ""
    agent_id: str = ""
    
    # Related events
    event_ids: List[str] = field(default_factory=list)
    event_count: int = 1
    
    # Correlation
    correlation_key: str = ""  # For deduplication
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    # Assignment
    assigned_to: str = ""
    acknowledged_by: str = ""
    acknowledged_at: datetime = None
    
    # Linked incident
    incident_id: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "organization_id": self.organization_id,
            "agent_id": self.agent_id,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "assigned_to": self.assigned_to,
            "incident_id": self.incident_id,
        }


@dataclass
class Incident:
    """Security incident for tracking and resolution"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    number: str = ""  # Human-readable: INC-2026-00001
    
    # Basic info
    title: str = ""
    description: str = ""
    incident_type: IncidentType = IncidentType.OTHER
    priority: IncidentPriority = IncidentPriority.P3_MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    
    # Organization context
    organization_id: str = ""
    workspace_id: str = ""
    
    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged_at: datetime = None
    contained_at: datetime = None
    resolved_at: datetime = None
    closed_at: datetime = None
    
    # SLA tracking
    response_due_at: datetime = None
    resolution_due_at: datetime = None
    sla_response_breached: bool = False
    sla_resolution_breached: bool = False
    
    # Assignment
    created_by: str = ""
    assigned_to: str = ""
    escalated_to: str = ""
    
    # Impact
    impact_score: int = 0  # 1-10
    affected_agents: List[str] = field(default_factory=list)
    affected_users_count: int = 0
    
    # Evidence
    related_alerts: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)
    evidence_artifacts: List[Dict] = field(default_factory=list)
    
    # Resolution
    root_cause: str = ""
    resolution_summary: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    
    # External tracking
    external_ticket_id: str = ""
    external_ticket_url: str = ""
    
    # Timeline
    timeline: List[Dict] = field(default_factory=list)
    comments: List[Dict] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.number:
            self.number = f"INC-{datetime.utcnow().strftime('%Y')}-{self.id[:8].upper()}"
        
        # Set SLA deadlines based on priority
        if self.priority in SLA_CONFIG:
            sla = SLA_CONFIG[self.priority]
            self.response_due_at = self.created_at + timedelta(minutes=sla["response_time_minutes"])
            self.resolution_due_at = self.created_at + timedelta(hours=sla["resolution_time_hours"])
    
    def add_timeline_event(self, event_type: str, description: str, user: str = "system"):
        """Add event to incident timeline"""
        self.timeline.append({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "description": description,
            "user": user,
        })
    
    def add_comment(self, content: str, user: str, is_internal: bool = True):
        """Add comment to incident"""
        self.comments.append({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "content": content,
            "user": user,
            "is_internal": is_internal,
        })
    
    def check_sla_breach(self) -> Tuple[bool, bool]:
        """Check if SLA is breached. Returns (response_breached, resolution_breached)"""
        now = datetime.utcnow()
        
        # Response SLA (if not acknowledged yet)
        if self.response_due_at and not self.acknowledged_at:
            if now > self.response_due_at:
                self.sla_response_breached = True
        
        # Resolution SLA (if not resolved yet)
        if self.resolution_due_at and self.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            if now > self.resolution_due_at:
                self.sla_resolution_breached = True
        
        return self.sla_response_breached, self.sla_resolution_breached
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "number": self.number,
            "title": self.title,
            "description": self.description,
            "incident_type": self.incident_type.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "created_at": self.created_at.isoformat(),
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "response_due_at": self.response_due_at.isoformat() if self.response_due_at else None,
            "resolution_due_at": self.resolution_due_at.isoformat() if self.resolution_due_at else None,
            "sla_response_breached": self.sla_response_breached,
            "sla_resolution_breached": self.sla_resolution_breached,
            "assigned_to": self.assigned_to,
            "impact_score": self.impact_score,
            "affected_agents": self.affected_agents,
            "root_cause": self.root_cause,
            "resolution_summary": self.resolution_summary,
            "external_ticket_id": self.external_ticket_id,
            "timeline": self.timeline,
            "comments": self.comments,
        }


@dataclass
class MonitoredAgent:
    """Agent registered for SOC monitoring"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Basic info
    name: str = ""
    description: str = ""
    agent_type: str = ""  # langchain, llamaindex, custom
    
    # Organization
    organization_id: str = ""
    workspace_id: str = ""
    environment: str = "production"  # production, staging, development
    
    # Status
    status: AgentStatus = AgentStatus.HEALTHY
    last_seen_at: datetime = None
    last_health_check: datetime = None
    
    # Configuration
    model_provider: str = ""
    model_name: str = ""
    tools: List[str] = field(default_factory=list)
    
    # Security settings
    firewall_enabled: bool = True
    sandbox_enabled: bool = False
    hitl_required: bool = False
    risk_threshold: float = 70.0
    
    # Metrics
    total_requests: int = 0
    blocked_requests: int = 0
    approval_requests: int = 0
    incidents_count: int = 0
    
    # Health metrics
    health_score: float = 100.0
    error_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "agent_type": self.agent_type,
            "organization_id": self.organization_id,
            "workspace_id": self.workspace_id,
            "environment": self.environment,
            "status": self.status.value,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "tools": self.tools,
            "firewall_enabled": self.firewall_enabled,
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "health_score": self.health_score,
            "error_rate": self.error_rate,
        }


@dataclass
class Playbook:
    """Automated response playbook"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    
    # Trigger conditions
    trigger_type: str = ""  # incident_created, alert_fired, event_received, schedule
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Actions
    steps: List[Dict] = field(default_factory=list)
    
    # Settings
    is_active: bool = True
    requires_approval: bool = False
    cooldown_minutes: int = 5
    
    # Stats
    execution_count: int = 0
    last_executed_at: datetime = None
    success_count: int = 0
    failure_count: int = 0
    
    # Metadata
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SOCMetrics:
    """SOC dashboard metrics"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    period: str = "24h"
    
    # Incident metrics
    total_incidents: int = 0
    open_incidents: int = 0
    incidents_by_priority: Dict[str, int] = field(default_factory=dict)
    incidents_by_type: Dict[str, int] = field(default_factory=dict)
    incidents_by_status: Dict[str, int] = field(default_factory=dict)
    
    # SLA metrics
    sla_compliance_rate: float = 100.0
    avg_response_time_minutes: float = 0.0
    avg_resolution_time_hours: float = 0.0
    sla_breaches_count: int = 0
    
    # Event metrics
    total_events: int = 0
    events_by_severity: Dict[str, int] = field(default_factory=dict)
    blocked_actions: int = 0
    allowed_actions: int = 0
    approval_requests: int = 0
    
    # Alert metrics
    total_alerts: int = 0
    new_alerts: int = 0
    
    # Agent metrics
    total_agents: int = 0
    healthy_agents: int = 0
    unhealthy_agents: int = 0
    quarantined_agents: int = 0
    
    # Threat metrics
    top_attack_types: List[Dict] = field(default_factory=list)
    top_targeted_agents: List[Dict] = field(default_factory=list)
    threat_trend: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "period": self.period,
            "incidents": {
                "total": self.total_incidents,
                "open": self.open_incidents,
                "by_priority": self.incidents_by_priority,
                "by_type": self.incidents_by_type,
                "by_status": self.incidents_by_status,
            },
            "sla": {
                "compliance_rate": self.sla_compliance_rate,
                "avg_response_time_minutes": self.avg_response_time_minutes,
                "avg_resolution_time_hours": self.avg_resolution_time_hours,
                "breaches": self.sla_breaches_count,
            },
            "events": {
                "total": self.total_events,
                "by_severity": self.events_by_severity,
                "blocked": self.blocked_actions,
                "allowed": self.allowed_actions,
                "approvals": self.approval_requests,
            },
            "alerts": {
                "total": self.total_alerts,
                "new": self.new_alerts,
            },
            "agents": {
                "total": self.total_agents,
                "healthy": self.healthy_agents,
                "unhealthy": self.unhealthy_agents,
                "quarantined": self.quarantined_agents,
            },
            "threats": {
                "top_attack_types": self.top_attack_types,
                "top_targeted_agents": self.top_targeted_agents,
            },
        }


# =============================================================================
# ALERT CORRELATION ENGINE
# =============================================================================

class AlertCorrelationEngine:
    """
    Correlates and deduplicates security events into alerts
    
    Features:
    - Event aggregation within time windows
    - Deduplication based on correlation keys
    - Alert severity escalation
    - Pattern-based correlation
    """
    
    def __init__(
        self,
        correlation_window_seconds: int = 300,  # 5 minutes
        dedup_window_seconds: int = 3600,       # 1 hour
    ):
        self.correlation_window = timedelta(seconds=correlation_window_seconds)
        self.dedup_window = timedelta(seconds=dedup_window_seconds)
        
        # Active alerts by correlation key
        self._active_alerts: Dict[str, Alert] = {}
        
        # Correlation rules
        self._correlation_rules: List[Dict] = []
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default correlation rules"""
        self._correlation_rules = [
            {
                "name": "same_agent_same_attack",
                "fields": ["agent_id", "event_type"],
                "window_seconds": 300,
                "threshold": 3,
                "severity_escalation": True,
            },
            {
                "name": "same_source_ip",
                "fields": ["source_ip", "event_type"],
                "window_seconds": 600,
                "threshold": 5,
                "severity_escalation": True,
            },
            {
                "name": "multi_agent_attack",
                "fields": ["organization_id", "event_type"],
                "window_seconds": 900,
                "threshold": 3,
                "severity_escalation": True,
            },
        ]
    
    def generate_correlation_key(self, event: SecurityEvent, fields: List[str]) -> str:
        """Generate correlation key from event fields"""
        values = []
        for field in fields:
            value = getattr(event, field, "") or ""
            values.append(str(value))
        
        key_string = "|".join(values)
        return hashlib.md5(key_string.encode()).hexdigest()[:16]
    
    def process_event(self, event: SecurityEvent) -> Optional[Alert]:
        """
        Process a security event and return an alert if triggered
        
        Returns:
            Alert if new or updated, None if event was absorbed into existing alert
        """
        # Generate correlation keys for each rule
        for rule in self._correlation_rules:
            correlation_key = self.generate_correlation_key(event, rule["fields"])
            full_key = f"{rule['name']}:{correlation_key}"
            
            # Check if alert exists for this key
            if full_key in self._active_alerts:
                alert = self._active_alerts[full_key]
                
                # Check if within dedup window
                if datetime.utcnow() - alert.last_seen < self.dedup_window:
                    # Update existing alert
                    alert.event_ids.append(event.id)
                    alert.event_count += 1
                    alert.last_seen = datetime.utcnow()
                    
                    # Escalate severity if threshold reached
                    if rule.get("severity_escalation") and alert.event_count >= rule.get("threshold", 3):
                        alert = self._escalate_severity(alert)
                    
                    return alert
        
        # Create new alert
        primary_key = self.generate_correlation_key(
            event, 
            ["agent_id", "event_type"]
        )
        
        alert = Alert(
            title=self._generate_alert_title(event),
            description=self._generate_alert_description(event),
            severity=event.severity,
            organization_id=event.organization_id,
            agent_id=event.agent_id,
            event_ids=[event.id],
            correlation_key=primary_key,
        )
        
        # Store in active alerts
        for rule in self._correlation_rules:
            correlation_key = self.generate_correlation_key(event, rule["fields"])
            full_key = f"{rule['name']}:{correlation_key}"
            self._active_alerts[full_key] = alert
        
        return alert
    
    def _generate_alert_title(self, event: SecurityEvent) -> str:
        """Generate alert title from event"""
        return f"{event.severity.value.upper()}: {event.event_type} on {event.agent_name or event.agent_id}"
    
    def _generate_alert_description(self, event: SecurityEvent) -> str:
        """Generate alert description from event"""
        lines = [
            f"Security event detected on agent {event.agent_name or event.agent_id}",
            f"Event Type: {event.event_type}",
            f"Decision: {event.decision}",
            f"Risk Score: {event.risk_score:.0f}",
        ]
        
        if event.tool_name:
            lines.append(f"Tool: {event.tool_name}")
        
        if event.violations:
            lines.append(f"Violations: {', '.join(event.violations)}")
        
        return "\n".join(lines)
    
    def _escalate_severity(self, alert: Alert) -> Alert:
        """Escalate alert severity"""
        severity_order = [
            EventSeverity.INFO,
            EventSeverity.LOW,
            EventSeverity.MEDIUM,
            EventSeverity.HIGH,
            EventSeverity.CRITICAL,
        ]
        
        current_idx = severity_order.index(alert.severity)
        if current_idx < len(severity_order) - 1:
            alert.severity = severity_order[current_idx + 1]
        
        return alert
    
    def cleanup_expired_alerts(self):
        """Remove expired alerts from active tracking"""
        now = datetime.utcnow()
        expired_keys = []
        
        for key, alert in self._active_alerts.items():
            if now - alert.last_seen > self.dedup_window:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._active_alerts[key]
        
        return len(expired_keys)


# =============================================================================
# INCIDENT MANAGER
# =============================================================================

class IncidentManager:
    """
    Manages the incident lifecycle
    
    Features:
    - Create incidents from alerts or manually
    - Assign and escalate incidents
    - Track SLA compliance
    - Generate incident reports
    """
    
    def __init__(self, integration_manager=None):
        self._incidents: Dict[str, Incident] = {}
        self._incident_counter = 0
        self.integration_manager = integration_manager
    
    def create_incident(
        self,
        title: str,
        description: str,
        incident_type: IncidentType,
        priority: IncidentPriority,
        organization_id: str,
        workspace_id: str = "",
        created_by: str = "system",
        affected_agents: List[str] = None,
        related_alerts: List[str] = None,
    ) -> Incident:
        """Create a new incident"""
        self._incident_counter += 1
        
        incident = Incident(
            number=f"INC-{datetime.utcnow().strftime('%Y')}-{self._incident_counter:05d}",
            title=title,
            description=description,
            incident_type=incident_type,
            priority=priority,
            organization_id=organization_id,
            workspace_id=workspace_id,
            created_by=created_by,
            affected_agents=affected_agents or [],
            related_alerts=related_alerts or [],
        )
        
        # Add creation to timeline
        incident.add_timeline_event("created", f"Incident created by {created_by}")
        
        self._incidents[incident.id] = incident
        
        logger.info(f"Created incident {incident.number}: {title}")
        
        return incident
    
    def create_incident_from_alert(self, alert: Alert, created_by: str = "system") -> Incident:
        """Create an incident from an alert"""
        # Determine incident type from alert
        incident_type = self._map_alert_to_incident_type(alert)
        
        # Determine priority from severity
        priority_map = {
            EventSeverity.CRITICAL: IncidentPriority.P1_CRITICAL,
            EventSeverity.HIGH: IncidentPriority.P2_HIGH,
            EventSeverity.MEDIUM: IncidentPriority.P3_MEDIUM,
            EventSeverity.LOW: IncidentPriority.P4_LOW,
            EventSeverity.INFO: IncidentPriority.P4_LOW,
        }
        
        incident = self.create_incident(
            title=alert.title,
            description=alert.description,
            incident_type=incident_type,
            priority=priority_map.get(alert.severity, IncidentPriority.P3_MEDIUM),
            organization_id=alert.organization_id,
            created_by=created_by,
            affected_agents=[alert.agent_id] if alert.agent_id else [],
            related_alerts=[alert.id],
        )
        
        # Link alert to incident
        alert.incident_id = incident.id
        alert.status = AlertStatus.ESCALATED
        
        return incident
    
    def _map_alert_to_incident_type(self, alert: Alert) -> IncidentType:
        """Map alert to incident type"""
        title_lower = alert.title.lower()
        
        if "injection" in title_lower or "prompt" in title_lower:
            return IncidentType.PROMPT_INJECTION
        elif "exfil" in title_lower or "leak" in title_lower:
            return IncidentType.DATA_EXFILTRATION
        elif "privilege" in title_lower or "escalat" in title_lower:
            return IncidentType.PRIVILEGE_ESCALATION
        elif "tool" in title_lower or "misuse" in title_lower:
            return IncidentType.TOOL_MISUSE
        elif "goal" in title_lower or "hijack" in title_lower:
            return IncidentType.GOAL_HIJACKING
        elif "backdoor" in title_lower:
            return IncidentType.BACKDOOR_DETECTED
        elif "rogue" in title_lower:
            return IncidentType.ROGUE_AGENT
        elif "policy" in title_lower or "violation" in title_lower:
            return IncidentType.POLICY_VIOLATION
        else:
            return IncidentType.SUSPICIOUS_ACTIVITY
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self._incidents.get(incident_id)
    
    def get_incident_by_number(self, number: str) -> Optional[Incident]:
        """Get incident by number"""
        for incident in self._incidents.values():
            if incident.number == number:
                return incident
        return None
    
    def list_incidents(
        self,
        organization_id: str = None,
        status: IncidentStatus = None,
        priority: IncidentPriority = None,
        assigned_to: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Incident], int]:
        """List incidents with filters"""
        results = []
        
        for incident in self._incidents.values():
            if organization_id and incident.organization_id != organization_id:
                continue
            if status and incident.status != status:
                continue
            if priority and incident.priority != priority:
                continue
            if assigned_to and incident.assigned_to != assigned_to:
                continue
            
            results.append(incident)
        
        # Sort by priority then created_at
        priority_order = [p.value for p in IncidentPriority]
        results.sort(key=lambda i: (
            priority_order.index(i.priority.value),
            i.created_at
        ))
        
        total = len(results)
        results = results[offset:offset + limit]
        
        return results, total
    
    def acknowledge_incident(self, incident_id: str, user: str) -> bool:
        """Acknowledge an incident"""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        
        incident.status = IncidentStatus.ACKNOWLEDGED
        incident.acknowledged_at = datetime.utcnow()
        incident.add_timeline_event("acknowledged", f"Acknowledged by {user}", user)
        
        logger.info(f"Incident {incident.number} acknowledged by {user}")
        return True
    
    def assign_incident(self, incident_id: str, assignee: str, assigner: str) -> bool:
        """Assign incident to a user"""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        
        old_assignee = incident.assigned_to
        incident.assigned_to = assignee
        incident.add_timeline_event(
            "assigned",
            f"Assigned to {assignee}" + (f" (from {old_assignee})" if old_assignee else ""),
            assigner
        )
        
        logger.info(f"Incident {incident.number} assigned to {assignee}")
        return True
    
    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        user: str,
        comment: str = ""
    ) -> bool:
        """Update incident status"""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        
        old_status = incident.status
        incident.status = new_status
        
        # Update timestamps based on status
        if new_status == IncidentStatus.ACKNOWLEDGED and not incident.acknowledged_at:
            incident.acknowledged_at = datetime.utcnow()
        elif new_status == IncidentStatus.CONTAINED:
            incident.contained_at = datetime.utcnow()
        elif new_status in [IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE]:
            incident.resolved_at = datetime.utcnow()
        elif new_status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.utcnow()
        
        incident.add_timeline_event(
            "status_change",
            f"Status changed from {old_status.value} to {new_status.value}" + 
            (f": {comment}" if comment else ""),
            user
        )
        
        logger.info(f"Incident {incident.number} status: {old_status.value} -> {new_status.value}")
        return True
    
    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        description: str,
        data: Dict[str, Any],
        user: str
    ) -> bool:
        """Add evidence to incident"""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        
        incident.evidence_artifacts.append({
            "id": str(uuid.uuid4()),
            "type": evidence_type,
            "description": description,
            "data": data,
            "added_by": user,
            "added_at": datetime.utcnow().isoformat(),
        })
        
        incident.add_timeline_event("evidence_added", f"Evidence added: {description}", user)
        return True
    
    def resolve_incident(
        self,
        incident_id: str,
        root_cause: str,
        resolution_summary: str,
        remediation_steps: List[str],
        user: str
    ) -> bool:
        """Resolve an incident"""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        
        incident.root_cause = root_cause
        incident.resolution_summary = resolution_summary
        incident.remediation_steps = remediation_steps
        
        return self.update_status(incident_id, IncidentStatus.RESOLVED, user, "Incident resolved")
    
    def check_all_sla_breaches(self) -> List[Incident]:
        """Check all open incidents for SLA breaches"""
        breached = []
        
        for incident in self._incidents.values():
            if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                continue
            
            response_breached, resolution_breached = incident.check_sla_breach()
            
            if response_breached or resolution_breached:
                breached.append(incident)
        
        return breached


# =============================================================================
# AGENT MONITOR
# =============================================================================

class AgentMonitor:
    """
    Monitors registered AI agents
    
    Features:
    - Agent inventory management
    - Health monitoring
    - Status tracking
    - Performance metrics
    """
    
    def __init__(self):
        self._agents: Dict[str, MonitoredAgent] = {}
        self._health_check_interval = 60  # seconds
    
    def register_agent(
        self,
        name: str,
        agent_type: str,
        organization_id: str,
        workspace_id: str = "",
        model_provider: str = "",
        model_name: str = "",
        tools: List[str] = None,
        **kwargs
    ) -> MonitoredAgent:
        """Register a new agent for monitoring"""
        agent = MonitoredAgent(
            name=name,
            agent_type=agent_type,
            organization_id=organization_id,
            workspace_id=workspace_id,
            model_provider=model_provider,
            model_name=model_name,
            tools=tools or [],
            **kwargs
        )
        
        self._agents[agent.id] = agent
        logger.info(f"Registered agent: {name} ({agent.id})")
        
        return agent
    
    def get_agent(self, agent_id: str) -> Optional[MonitoredAgent]:
        """Get agent by ID"""
        return self._agents.get(agent_id)
    
    def get_agent_by_name(self, name: str, organization_id: str) -> Optional[MonitoredAgent]:
        """Get agent by name within organization"""
        for agent in self._agents.values():
            if agent.name == name and agent.organization_id == organization_id:
                return agent
        return None
    
    def list_agents(
        self,
        organization_id: str = None,
        status: AgentStatus = None,
        workspace_id: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[MonitoredAgent], int]:
        """List agents with filters"""
        results = []
        
        for agent in self._agents.values():
            if organization_id and agent.organization_id != organization_id:
                continue
            if status and agent.status != status:
                continue
            if workspace_id and agent.workspace_id != workspace_id:
                continue
            
            results.append(agent)
        
        # Sort by name
        results.sort(key=lambda a: a.name)
        
        total = len(results)
        results = results[offset:offset + limit]
        
        return results, total
    
    def update_agent_status(self, agent_id: str, status: AgentStatus) -> bool:
        """Update agent status"""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        
        old_status = agent.status
        agent.status = status
        
        logger.info(f"Agent {agent.name} status: {old_status.value} -> {status.value}")
        return True
    
    def record_heartbeat(self, agent_id: str) -> bool:
        """Record agent heartbeat"""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        
        agent.last_seen_at = datetime.utcnow()
        
        # Update status if was offline
        if agent.status == AgentStatus.OFFLINE:
            agent.status = AgentStatus.HEALTHY
        
        return True
    
    def record_event(
        self,
        agent_id: str,
        decision: str,
        risk_score: float = 0.0
    ) -> bool:
        """Record an event for agent metrics"""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        
        agent.total_requests += 1
        
        if decision == "block":
            agent.blocked_requests += 1
        elif decision == "require_approval":
            agent.approval_requests += 1
        
        agent.last_seen_at = datetime.utcnow()
        return True
    
    def quarantine_agent(self, agent_id: str, reason: str) -> bool:
        """Quarantine an agent"""
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        
        agent.status = AgentStatus.QUARANTINED
        agent.firewall_enabled = True
        agent.hitl_required = True
        
        logger.warning(f"Agent {agent.name} quarantined: {reason}")
        return True
    
    def check_offline_agents(self, timeout_seconds: int = 300) -> List[MonitoredAgent]:
        """Find agents that haven't reported in"""
        offline = []
        now = datetime.utcnow()
        
        for agent in self._agents.values():
            if agent.status == AgentStatus.QUARANTINED:
                continue
            
            if agent.last_seen_at:
                if (now - agent.last_seen_at).total_seconds() > timeout_seconds:
                    agent.status = AgentStatus.OFFLINE
                    offline.append(agent)
        
        return offline
    
    def get_agent_metrics(self, agent_id: str) -> Dict[str, Any]:
        """Get metrics for an agent"""
        agent = self._agents.get(agent_id)
        if not agent:
            return {}
        
        block_rate = (
            agent.blocked_requests / agent.total_requests * 100
            if agent.total_requests > 0 else 0
        )
        
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": agent.status.value,
            "health_score": agent.health_score,
            "total_requests": agent.total_requests,
            "blocked_requests": agent.blocked_requests,
            "block_rate": block_rate,
            "approval_requests": agent.approval_requests,
            "incidents_count": agent.incidents_count,
            "error_rate": agent.error_rate,
            "avg_response_time_ms": agent.avg_response_time_ms,
            "last_seen": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        }


# =============================================================================
# SOC COMMAND CENTER
# =============================================================================

class SOCCommandCenter:
    """
    Main SOC Command Center orchestrating all security operations
    
    Features:
    - Unified event processing
    - Incident management
    - Agent monitoring
    - Metrics and dashboards
    - Playbook automation
    """
    
    def __init__(self, integration_manager=None):
        self.integration_manager = integration_manager
        
        # Components
        self.correlation_engine = AlertCorrelationEngine()
        self.incident_manager = IncidentManager(integration_manager)
        self.agent_monitor = AgentMonitor()
        
        # Storage
        self._events: List[SecurityEvent] = []
        self._alerts: Dict[str, Alert] = {}
        self._playbooks: Dict[str, Playbook] = {}
        
        # Event handlers
        self._event_handlers: List[Callable] = []
        self._alert_handlers: List[Callable] = []
        
        # Running state
        self._running = False
        self._event_queue: asyncio.Queue = None
    
    # =========================================================================
    # EVENT PROCESSING
    # =========================================================================
    
    async def process_event(self, event: SecurityEvent) -> Optional[Alert]:
        """
        Process a security event through the SOC pipeline
        
        1. Store event
        2. Correlate into alerts
        3. Update agent metrics
        4. Trigger playbooks
        5. Send notifications
        """
        # Store event
        self._events.append(event)
        
        # Update agent metrics
        self.agent_monitor.record_event(
            event.agent_id,
            event.decision,
            event.risk_score
        )
        
        # Correlate into alert
        alert = self.correlation_engine.process_event(event)
        
        if alert:
            # Store/update alert
            self._alerts[alert.id] = alert
            
            # Call alert handlers
            for handler in self._alert_handlers:
                try:
                    await handler(alert)
                except Exception as e:
                    logger.error(f"Alert handler error: {e}")
            
            # Check if should create incident
            if self._should_create_incident(alert):
                incident = self.incident_manager.create_incident_from_alert(alert)
                
                # Send notifications
                if self.integration_manager:
                    from .integrations.integration_service import Notification, NotificationType, NotificationPriority
                    
                    notification = Notification(
                        notification_type=NotificationType.INCIDENT,
                        priority=self._map_severity_to_priority(alert.severity),
                        title=f"New Incident: {incident.number}",
                        message=incident.description,
                        details={
                            "Incident Number": incident.number,
                            "Priority": incident.priority.value,
                            "Type": incident.incident_type.value,
                            "Agent": event.agent_name or event.agent_id,
                        },
                        incident_id=incident.id,
                    )
                    
                    await self.integration_manager.send_notification(notification)
        
        # Call event handlers
        for handler in self._event_handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")
        
        return alert
    
    def _should_create_incident(self, alert: Alert) -> bool:
        """Determine if alert should trigger incident creation"""
        # Create incident for high/critical severity
        if alert.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
            return True
        
        # Create incident if event count exceeds threshold
        if alert.event_count >= 5:
            return True
        
        return False
    
    def _map_severity_to_priority(self, severity: EventSeverity):
        """Map severity to notification priority"""
        from .integrations.integration_service import NotificationPriority
        
        mapping = {
            EventSeverity.CRITICAL: NotificationPriority.CRITICAL,
            EventSeverity.HIGH: NotificationPriority.HIGH,
            EventSeverity.MEDIUM: NotificationPriority.MEDIUM,
            EventSeverity.LOW: NotificationPriority.LOW,
            EventSeverity.INFO: NotificationPriority.INFO,
        }
        return mapping.get(severity, NotificationPriority.MEDIUM)
    
    def add_event_handler(self, handler: Callable):
        """Add custom event handler"""
        self._event_handlers.append(handler)
    
    def add_alert_handler(self, handler: Callable):
        """Add custom alert handler"""
        self._alert_handlers.append(handler)
    
    # =========================================================================
    # ALERT MANAGEMENT
    # =========================================================================
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID"""
        return self._alerts.get(alert_id)
    
    def list_alerts(
        self,
        organization_id: str = None,
        status: AlertStatus = None,
        severity: EventSeverity = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Alert], int]:
        """List alerts with filters"""
        results = []
        
        for alert in self._alerts.values():
            if organization_id and alert.organization_id != organization_id:
                continue
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
            
            results.append(alert)
        
        # Sort by severity then last_seen
        severity_order = [s.value for s in EventSeverity]
        results.sort(key=lambda a: (
            severity_order.index(a.severity.value),
            -a.last_seen.timestamp()
        ))
        
        total = len(results)
        results = results[offset:offset + limit]
        
        return results, total
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user
        alert.acknowledged_at = datetime.utcnow()
        
        return True
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        
        alert.status = AlertStatus.RESOLVED
        return True
    
    def escalate_alert_to_incident(self, alert_id: str, user: str = "system") -> Optional[Incident]:
        """Manually escalate alert to incident"""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        
        return self.incident_manager.create_incident_from_alert(alert, user)
    
    # =========================================================================
    # METRICS AND DASHBOARDS
    # =========================================================================
    
    def get_metrics(self, organization_id: str = None, period: str = "24h") -> SOCMetrics:
        """Get SOC metrics for dashboard"""
        metrics = SOCMetrics(period=period)
        
        # Calculate time range
        if period == "1h":
            start_time = datetime.utcnow() - timedelta(hours=1)
        elif period == "24h":
            start_time = datetime.utcnow() - timedelta(hours=24)
        elif period == "7d":
            start_time = datetime.utcnow() - timedelta(days=7)
        elif period == "30d":
            start_time = datetime.utcnow() - timedelta(days=30)
        else:
            start_time = datetime.utcnow() - timedelta(hours=24)
        
        # Incident metrics
        incidents, _ = self.incident_manager.list_incidents(organization_id=organization_id)
        period_incidents = [i for i in incidents if i.created_at >= start_time]
        
        metrics.total_incidents = len(period_incidents)
        metrics.open_incidents = len([i for i in period_incidents if i.status in [
            IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING
        ]])
        
        for incident in period_incidents:
            # By priority
            priority = incident.priority.value
            metrics.incidents_by_priority[priority] = metrics.incidents_by_priority.get(priority, 0) + 1
            
            # By type
            inc_type = incident.incident_type.value
            metrics.incidents_by_type[inc_type] = metrics.incidents_by_type.get(inc_type, 0) + 1
            
            # By status
            status = incident.status.value
            metrics.incidents_by_status[status] = metrics.incidents_by_status.get(status, 0) + 1
            
            # SLA tracking
            if incident.sla_response_breached or incident.sla_resolution_breached:
                metrics.sla_breaches_count += 1
        
        # Calculate SLA compliance
        if metrics.total_incidents > 0:
            metrics.sla_compliance_rate = (
                (metrics.total_incidents - metrics.sla_breaches_count) / metrics.total_incidents * 100
            )
        
        # Calculate average response/resolution times
        response_times = []
        resolution_times = []
        
        for incident in period_incidents:
            if incident.acknowledged_at and incident.created_at:
                response_time = (incident.acknowledged_at - incident.created_at).total_seconds() / 60
                response_times.append(response_time)
            
            if incident.resolved_at and incident.created_at:
                resolution_time = (incident.resolved_at - incident.created_at).total_seconds() / 3600
                resolution_times.append(resolution_time)
        
        if response_times:
            metrics.avg_response_time_minutes = sum(response_times) / len(response_times)
        if resolution_times:
            metrics.avg_resolution_time_hours = sum(resolution_times) / len(resolution_times)
        
        # Event metrics
        period_events = [e for e in self._events if e.timestamp >= start_time]
        if organization_id:
            period_events = [e for e in period_events if e.organization_id == organization_id]
        
        metrics.total_events = len(period_events)
        
        for event in period_events:
            severity = event.severity.value
            metrics.events_by_severity[severity] = metrics.events_by_severity.get(severity, 0) + 1
            
            if event.decision == "block":
                metrics.blocked_actions += 1
            elif event.decision == "allow":
                metrics.allowed_actions += 1
            elif event.decision == "require_approval":
                metrics.approval_requests += 1
        
        # Alert metrics
        period_alerts = [a for a in self._alerts.values() if a.created_at >= start_time]
        if organization_id:
            period_alerts = [a for a in period_alerts if a.organization_id == organization_id]
        
        metrics.total_alerts = len(period_alerts)
        metrics.new_alerts = len([a for a in period_alerts if a.status == AlertStatus.NEW])
        
        # Agent metrics
        agents, _ = self.agent_monitor.list_agents(organization_id=organization_id)
        
        metrics.total_agents = len(agents)
        metrics.healthy_agents = len([a for a in agents if a.status == AgentStatus.HEALTHY])
        metrics.unhealthy_agents = len([a for a in agents if a.status in [
            AgentStatus.DEGRADED, AgentStatus.UNHEALTHY, AgentStatus.OFFLINE
        ]])
        metrics.quarantined_agents = len([a for a in agents if a.status == AgentStatus.QUARANTINED])
        
        # Top attack types
        attack_counts = defaultdict(int)
        for event in period_events:
            if event.decision == "block":
                attack_counts[event.event_type] += 1
        
        metrics.top_attack_types = [
            {"type": k, "count": v}
            for k, v in sorted(attack_counts.items(), key=lambda x: -x[1])[:5]
        ]
        
        # Top targeted agents
        agent_attack_counts = defaultdict(int)
        for event in period_events:
            if event.decision == "block":
                agent_attack_counts[event.agent_name or event.agent_id] += 1
        
        metrics.top_targeted_agents = [
            {"agent": k, "count": v}
            for k, v in sorted(agent_attack_counts.items(), key=lambda x: -x[1])[:5]
        ]
        
        return metrics
    
    def get_threat_level(self, organization_id: str = None) -> str:
        """Get current threat level (green/yellow/orange/red)"""
        metrics = self.get_metrics(organization_id, period="1h")
        
        # Calculate threat score
        score = 0
        
        # Critical incidents
        score += metrics.incidents_by_priority.get("p1_critical", 0) * 40
        score += metrics.incidents_by_priority.get("p2_high", 0) * 20
        
        # Critical events
        score += metrics.events_by_severity.get("critical", 0) * 10
        score += metrics.events_by_severity.get("high", 0) * 5
        
        # SLA breaches
        score += metrics.sla_breaches_count * 15
        
        # Quarantined agents
        score += metrics.quarantined_agents * 25
        
        # Determine level
        if score >= 100:
            return "red"
        elif score >= 50:
            return "orange"
        elif score >= 20:
            return "yellow"
        else:
            return "green"
    
    # =========================================================================
    # PLAYBOOKS
    # =========================================================================
    
    def register_playbook(self, playbook: Playbook):
        """Register an automation playbook"""
        self._playbooks[playbook.id] = playbook
        logger.info(f"Registered playbook: {playbook.name}")
    
    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get playbook by ID"""
        return self._playbooks.get(playbook_id)
    
    def list_playbooks(self, is_active: bool = None) -> List[Playbook]:
        """List all playbooks"""
        results = list(self._playbooks.values())
        
        if is_active is not None:
            results = [p for p in results if p.is_active == is_active]
        
        return results
    
    async def execute_playbook(
        self,
        playbook_id: str,
        context: Dict[str, Any]
    ) -> Tuple[bool, List[Dict]]:
        """
        Execute a playbook
        
        Returns: (success, step_results)
        """
        playbook = self._playbooks.get(playbook_id)
        if not playbook or not playbook.is_active:
            return False, []
        
        # Check cooldown
        if playbook.last_executed_at:
            cooldown_end = playbook.last_executed_at + timedelta(minutes=playbook.cooldown_minutes)
            if datetime.utcnow() < cooldown_end:
                logger.info(f"Playbook {playbook.name} in cooldown")
                return False, [{"step": "cooldown", "skipped": True}]
        
        results = []
        success = True
        
        for i, step in enumerate(playbook.steps):
            step_result = await self._execute_playbook_step(step, context)
            results.append({
                "step": i + 1,
                "action": step.get("action"),
                **step_result
            })
            
            if not step_result.get("success", False):
                success = False
                if step.get("stop_on_failure", True):
                    break
        
        # Update playbook stats
        playbook.execution_count += 1
        playbook.last_executed_at = datetime.utcnow()
        
        if success:
            playbook.success_count += 1
        else:
            playbook.failure_count += 1
        
        return success, results
    
    async def _execute_playbook_step(
        self,
        step: Dict,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single playbook step"""
        action = step.get("action")
        params = step.get("params", {})
        
        try:
            if action == "send_notification":
                if self.integration_manager:
                    from .integrations.integration_service import Notification, NotificationType, NotificationPriority
                    
                    notification = Notification(
                        notification_type=NotificationType(params.get("type", "alert")),
                        priority=NotificationPriority(params.get("priority", "medium")),
                        title=params.get("title", "").format(**context),
                        message=params.get("message", "").format(**context),
                    )
                    
                    await self.integration_manager.send_notification(
                        notification,
                        integrations=params.get("integrations")
                    )
                    
                    return {"success": True, "message": "Notification sent"}
            
            elif action == "quarantine_agent":
                agent_id = params.get("agent_id") or context.get("agent_id")
                if agent_id:
                    self.agent_monitor.quarantine_agent(
                        agent_id,
                        params.get("reason", "Playbook triggered")
                    )
                    return {"success": True, "message": f"Agent {agent_id} quarantined"}
            
            elif action == "create_incident":
                incident = self.incident_manager.create_incident(
                    title=params.get("title", "").format(**context),
                    description=params.get("description", "").format(**context),
                    incident_type=IncidentType(params.get("type", "other")),
                    priority=IncidentPriority(params.get("priority", "p3_medium")),
                    organization_id=context.get("organization_id", ""),
                    created_by="playbook",
                )
                return {"success": True, "incident_id": incident.id}
            
            elif action == "create_jira_ticket":
                if self.integration_manager:
                    jira = self.integration_manager.get_integration("jira")
                    if jira:
                        result = await jira.create_incident_ticket(
                            incident_id=context.get("incident_id", ""),
                            title=params.get("title", "").format(**context),
                            description=params.get("description", "").format(**context),
                            priority=params.get("priority", "medium"),
                            details=context,
                        )
                        return {"success": result.success, "ticket": result.external_id}
            
            elif action == "wait":
                await asyncio.sleep(params.get("seconds", 5))
                return {"success": True, "message": "Wait completed"}
            
            elif action == "log":
                logger.info(f"Playbook log: {params.get('message', '').format(**context)}")
                return {"success": True}
            
            return {"success": False, "error": f"Unknown action: {action}"}
            
        except Exception as e:
            logger.error(f"Playbook step failed: {e}")
            return {"success": False, "error": str(e)}
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    
    async def start(self):
        """Start the SOC Command Center"""
        self._running = True
        self._event_queue = asyncio.Queue()
        
        logger.info("SOC Command Center started")
        
        # Start background tasks
        asyncio.create_task(self._sla_monitor_loop())
        asyncio.create_task(self._agent_health_check_loop())
        asyncio.create_task(self._cleanup_loop())
    
    async def stop(self):
        """Stop the SOC Command Center"""
        self._running = False
        logger.info("SOC Command Center stopped")
    
    async def _sla_monitor_loop(self):
        """Background task to monitor SLA breaches"""
        while self._running:
            try:
                breached = self.incident_manager.check_all_sla_breaches()
                
                for incident in breached:
                    logger.warning(f"SLA breach for incident {incident.number}")
                    
                    # Send escalation notification
                    if self.integration_manager:
                        from .integrations.integration_service import Notification, NotificationType, NotificationPriority
                        
                        notification = Notification(
                            notification_type=NotificationType.INCIDENT,
                            priority=NotificationPriority.HIGH,
                            title=f"SLA Breach: {incident.number}",
                            message=f"Incident {incident.number} has breached SLA",
                            details={
                                "Incident": incident.number,
                                "Priority": incident.priority.value,
                                "Response Breached": incident.sla_response_breached,
                                "Resolution Breached": incident.sla_resolution_breached,
                            },
                            incident_id=incident.id,
                        )
                        
                        await self.integration_manager.send_notification(notification)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"SLA monitor error: {e}")
                await asyncio.sleep(60)
    
    async def _agent_health_check_loop(self):
        """Background task to check agent health"""
        while self._running:
            try:
                offline = self.agent_monitor.check_offline_agents()
                
                for agent in offline:
                    logger.warning(f"Agent offline: {agent.name}")
                
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Agent health check error: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_loop(self):
        """Background task to cleanup old data"""
        while self._running:
            try:
                # Cleanup expired alerts
                removed = self.correlation_engine.cleanup_expired_alerts()
                if removed > 0:
                    logger.info(f"Cleaned up {removed} expired alerts")
                
                # Cleanup old events (keep last 24 hours)
                cutoff = datetime.utcnow() - timedelta(hours=24)
                original_count = len(self._events)
                self._events = [e for e in self._events if e.timestamp >= cutoff]
                removed_events = original_count - len(self._events)
                
                if removed_events > 0:
                    logger.info(f"Cleaned up {removed_events} old events")
                
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
                await asyncio.sleep(300)


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    async def test_soc():
        print("=" * 60)
        print("Testing SOC Command Center")
        print("=" * 60)
        
        # Create SOC
        soc = SOCCommandCenter()
        
        # Register agents
        print("\n📡 Registering agents...")
        agent1 = soc.agent_monitor.register_agent(
            name="customer-service-bot",
            agent_type="langchain",
            organization_id="org-123",
            model_provider="openai",
            model_name="gpt-4",
            tools=["database_query", "send_email", "create_ticket"],
        )
        
        agent2 = soc.agent_monitor.register_agent(
            name="data-analysis-agent",
            agent_type="llamaindex",
            organization_id="org-123",
            model_provider="anthropic",
            model_name="claude-3-opus",
            tools=["sql_query", "chart_generator"],
        )
        
        print(f"  Registered: {agent1.name}")
        print(f"  Registered: {agent2.name}")
        
        # Process events
        print("\n🔔 Processing security events...")
        
        events = [
            SecurityEvent(
                organization_id="org-123",
                agent_id=agent1.id,
                agent_name="customer-service-bot",
                event_type="prompt_injection",
                severity=EventSeverity.HIGH,
                tool_name="database_query",
                decision="block",
                risk_score=85,
                violations=["LLM01"],
            ),
            SecurityEvent(
                organization_id="org-123",
                agent_id=agent1.id,
                agent_name="customer-service-bot",
                event_type="prompt_injection",
                severity=EventSeverity.HIGH,
                tool_name="database_query",
                decision="block",
                risk_score=88,
                violations=["LLM01"],
            ),
            SecurityEvent(
                organization_id="org-123",
                agent_id=agent1.id,
                agent_name="customer-service-bot",
                event_type="prompt_injection",
                severity=EventSeverity.CRITICAL,
                tool_name="database_query",
                decision="block",
                risk_score=95,
                violations=["LLM01", "ASI02"],
            ),
        ]
        
        for event in events:
            alert = await soc.process_event(event)
            if alert:
                print(f"  Alert: {alert.title} (count: {alert.event_count})")
        
        # List alerts
        print("\n📋 Active alerts:")
        alerts, total = soc.list_alerts()
        for alert in alerts:
            print(f"  - {alert.title} ({alert.severity.value}, events: {alert.event_count})")
        
        # List incidents
        print("\n🚨 Incidents:")
        incidents, total = soc.incident_manager.list_incidents()
        for incident in incidents:
            print(f"  - {incident.number}: {incident.title} ({incident.priority.value})")
        
        # Get metrics
        print("\n📊 SOC Metrics:")
        metrics = soc.get_metrics()
        print(f"  Total Events: {metrics.total_events}")
        print(f"  Total Alerts: {metrics.total_alerts}")
        print(f"  Total Incidents: {metrics.total_incidents}")
        print(f"  Blocked Actions: {metrics.blocked_actions}")
        print(f"  Threat Level: {soc.get_threat_level()}")
        
        # Test incident lifecycle
        print("\n🔧 Testing incident lifecycle...")
        if incidents:
            incident = incidents[0]
            
            # Acknowledge
            soc.incident_manager.acknowledge_incident(incident.id, "analyst1")
            print(f"  Acknowledged: {incident.number}")
            
            # Assign
            soc.incident_manager.assign_incident(incident.id, "analyst2", "analyst1")
            print(f"  Assigned to: analyst2")
            
            # Add comment
            incident.add_comment("Starting investigation", "analyst2")
            print(f"  Added comment")
            
            # Check SLA
            response_breach, resolution_breach = incident.check_sla_breach()
            print(f"  SLA Status - Response: {'⚠️' if response_breach else '✅'}, Resolution: {'⚠️' if resolution_breach else '✅'}")
        
        # Test agent metrics
        print("\n🤖 Agent Metrics:")
        for agent_id in [agent1.id, agent2.id]:
            metrics = soc.agent_monitor.get_agent_metrics(agent_id)
            print(f"  {metrics['agent_name']}:")
            print(f"    Status: {metrics['status']}")
            print(f"    Total Requests: {metrics['total_requests']}")
            print(f"    Blocked: {metrics['blocked_requests']}")
        
        # Test playbook
        print("\n📜 Testing Playbook...")
        playbook = Playbook(
            name="Auto-respond to critical alerts",
            trigger_type="alert_fired",
            trigger_conditions={"severity": "critical"},
            steps=[
                {"action": "log", "params": {"message": "Critical alert detected for {agent_name}"}},
                {"action": "quarantine_agent", "params": {"reason": "Critical security alert"}},
            ],
        )
        soc.register_playbook(playbook)
        
        context = {
            "agent_id": agent1.id,
            "agent_name": "customer-service-bot",
            "organization_id": "org-123",
        }
        
        success, results = await soc.execute_playbook(playbook.id, context)
        print(f"  Playbook executed: {'✅' if success else '❌'}")
        for result in results:
            print(f"    Step {result['step']}: {result.get('action', 'unknown')} - {result.get('message', result.get('error', 'done'))}")
        
        print("\n✅ SOC Command Center tests complete!")
    
    asyncio.run(test_soc())

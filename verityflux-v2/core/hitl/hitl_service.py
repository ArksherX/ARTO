#!/usr/bin/env python3
"""
VerityFlux Enterprise - Human-in-the-Loop (HITL) System
Comprehensive approval workflow system for AI agent oversight

Features:
- Risk-based approval routing
- Multi-level approval workflows
- Time-based auto-escalation
- Approval policies and rules
- Audit trail and compliance
- Interactive approval via Slack/Email
- Bulk approval operations
- Approval analytics
"""

import os
import json
import asyncio
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verityflux.hitl")


# =============================================================================
# ENUMS
# =============================================================================

class ApprovalStatus(Enum):
    """Status of an approval request"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    ESCALATED = "escalated"
    CANCELLED = "cancelled"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


class ApprovalDecision(Enum):
    """Decisions that can be made on an approval"""
    APPROVE = "approve"
    APPROVE_ONCE = "approve_once"       # Approve this action only
    APPROVE_SESSION = "approve_session"  # Approve for this session
    APPROVE_ALWAYS = "approve_always"    # Create allow rule
    DENY = "deny"
    DENY_ALWAYS = "deny_always"          # Create block rule
    ESCALATE = "escalate"
    REQUEST_INFO = "request_info"


class RiskLevel(Enum):
    """Risk levels for actions"""
    CRITICAL = "critical"   # Always require approval
    HIGH = "high"           # Require approval above threshold
    MEDIUM = "medium"       # May require approval
    LOW = "low"             # Usually auto-approve
    MINIMAL = "minimal"     # Always auto-approve


class ApprovalType(Enum):
    """Types of approval requests"""
    TOOL_EXECUTION = "tool_execution"
    DATA_ACCESS = "data_access"
    EXTERNAL_COMMUNICATION = "external_communication"
    CODE_EXECUTION = "code_execution"
    CONFIGURATION_CHANGE = "configuration_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BULK_OPERATION = "bulk_operation"
    SENSITIVE_ACTION = "sensitive_action"
    CUSTOM = "custom"


class EscalationReason(Enum):
    """Reasons for escalation"""
    TIMEOUT = "timeout"
    MANUAL = "manual"
    RISK_THRESHOLD = "risk_threshold"
    POLICY_REQUIREMENT = "policy_requirement"
    REVIEWER_UNAVAILABLE = "reviewer_unavailable"


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class HITLConfig:
    """HITL system configuration"""
    
    # Timeouts
    default_timeout_minutes: int = 30
    critical_timeout_minutes: int = 15
    escalation_timeout_minutes: int = 60
    
    # Auto-decisions
    enable_auto_approve: bool = True
    auto_approve_below_risk: float = 30.0
    auto_deny_above_risk: float = 95.0
    
    # Escalation
    enable_auto_escalation: bool = True
    escalation_after_minutes: int = 15
    max_escalation_levels: int = 3
    
    # Notifications
    notification_channels: List[str] = field(default_factory=lambda: ["slack", "email"])
    reminder_interval_minutes: int = 10
    max_reminders: int = 3
    
    # Bulk operations
    bulk_approval_enabled: bool = True
    bulk_approval_max_items: int = 50
    
    # Audit
    require_justification: bool = True
    min_justification_length: int = 10


DEFAULT_CONFIG = HITLConfig()


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ApprovalContext:
    """Context for an action requiring approval"""
    
    # Agent context
    agent_id: str = ""
    agent_name: str = ""
    session_id: str = ""
    
    # User context
    user_id: str = ""
    user_name: str = ""
    
    # Organization
    organization_id: str = ""
    workspace_id: str = ""
    
    # Action details
    tool_name: str = ""
    action_type: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # AI reasoning
    reasoning_chain: List[str] = field(default_factory=list)
    original_goal: str = ""
    expected_outcome: str = ""
    
    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    
    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalRequest:
    """Request for human approval"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Type and status
    approval_type: ApprovalType = ApprovalType.TOOL_EXECUTION
    status: ApprovalStatus = ApprovalStatus.PENDING
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # Title and description
    title: str = ""
    description: str = ""
    
    # Context
    context: ApprovalContext = field(default_factory=ApprovalContext)
    
    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = None
    decided_at: datetime = None
    
    # Assignment
    requested_by: str = ""  # Usually the agent
    assigned_to: List[str] = field(default_factory=list)  # Potential approvers
    decided_by: str = ""
    
    # Decision
    decision: ApprovalDecision = None
    justification: str = ""
    conditions: List[str] = field(default_factory=list)  # Conditions attached to approval
    
    # Escalation
    escalation_level: int = 0
    escalation_history: List[Dict] = field(default_factory=list)
    
    # Notifications
    notification_count: int = 0
    last_notification_at: datetime = None
    
    # Linking
    related_requests: List[str] = field(default_factory=list)
    parent_request_id: str = ""  # For escalated requests
    
    # Callback
    callback_url: str = ""
    callback_token: str = ""
    
    def __post_init__(self):
        if not self.expires_at:
            timeout = DEFAULT_CONFIG.default_timeout_minutes
            if self.risk_level == RiskLevel.CRITICAL:
                timeout = DEFAULT_CONFIG.critical_timeout_minutes
            self.expires_at = self.created_at + timedelta(minutes=timeout)
        
        if not self.callback_token:
            self.callback_token = hashlib.sha256(
                f"{self.id}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:32]
    
    def is_expired(self) -> bool:
        """Check if request has expired"""
        return datetime.utcnow() > self.expires_at and self.status == ApprovalStatus.PENDING
    
    def time_remaining(self) -> timedelta:
        """Get time remaining before expiration"""
        if self.status != ApprovalStatus.PENDING:
            return timedelta(0)
        remaining = self.expires_at - datetime.utcnow()
        return max(remaining, timedelta(0))
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "approval_type": self.approval_type.value,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "title": self.title,
            "description": self.description,
            "context": {
                "agent_id": self.context.agent_id,
                "agent_name": self.context.agent_name,
                "tool_name": self.context.tool_name,
                "action_type": self.context.action_type,
                "parameters": self.context.parameters,
                "risk_score": self.context.risk_score,
                "risk_factors": self.context.risk_factors,
                "reasoning_chain": self.context.reasoning_chain,
                "original_goal": self.context.original_goal,
            },
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "assigned_to": self.assigned_to,
            "decided_by": self.decided_by,
            "decision": self.decision.value if self.decision else None,
            "justification": self.justification,
            "escalation_level": self.escalation_level,
            "time_remaining_seconds": self.time_remaining().total_seconds(),
        }


@dataclass
class ApprovalPolicy:
    """Policy defining approval requirements"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    
    # Scope
    organization_id: str = ""
    workspace_ids: List[str] = field(default_factory=list)  # Empty = all workspaces
    agent_ids: List[str] = field(default_factory=list)  # Empty = all agents
    
    # Conditions (all must match)
    tool_patterns: List[str] = field(default_factory=list)  # Regex patterns
    action_types: List[ApprovalType] = field(default_factory=list)
    min_risk_score: float = 0.0
    
    # Requirements
    require_approval: bool = True
    min_approvers: int = 1
    require_justification: bool = True
    
    # Approvers
    approver_roles: List[str] = field(default_factory=list)  # e.g., ["admin", "security_analyst"]
    approver_users: List[str] = field(default_factory=list)  # Specific user IDs
    
    # Auto-decisions
    auto_approve_below_risk: float = None  # Override global
    auto_deny_above_risk: float = None
    
    # Escalation
    escalation_chain: List[List[str]] = field(default_factory=list)  # Levels of approvers
    escalation_timeout_minutes: int = 15
    
    # Settings
    is_active: bool = True
    priority: int = 0  # Higher = evaluated first
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""


@dataclass
class ApprovalRule:
    """Pre-configured approval/denial rule"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    
    # Rule type
    rule_type: str = "allow"  # allow, deny
    
    # Matching conditions
    organization_id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    action_pattern: str = ""  # Regex pattern for action
    parameter_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Validity
    is_active: bool = True
    expires_at: datetime = None
    use_count: int = 0
    max_uses: int = -1  # -1 = unlimited
    
    # Scope
    scope: str = "always"  # always, session, once
    session_id: str = ""
    
    # Audit
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    created_from_request_id: str = ""


@dataclass
class ApprovalAuditEntry:
    """Audit log entry for approval actions"""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Request reference
    request_id: str = ""
    
    # Action
    action: str = ""  # created, viewed, decided, escalated, expired, etc.
    actor: str = ""  # User or system
    actor_type: str = "user"  # user, system, agent
    
    # Details
    previous_status: str = ""
    new_status: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    ip_address: str = ""
    user_agent: str = ""


# =============================================================================
# APPROVAL ROUTER
# =============================================================================

class ApprovalRouter:
    """
    Routes approval requests to appropriate approvers based on policies
    
    Features:
    - Policy-based routing
    - Role-based assignment
    - Load balancing among approvers
    - Escalation chain management
    """
    
    def __init__(self):
        self._policies: Dict[str, ApprovalPolicy] = {}
        self._approver_availability: Dict[str, bool] = {}
        self._approver_load: Dict[str, int] = {}
    
    def add_policy(self, policy: ApprovalPolicy):
        """Add an approval policy"""
        self._policies[policy.id] = policy
        logger.info(f"Added approval policy: {policy.name}")
    
    def remove_policy(self, policy_id: str):
        """Remove an approval policy"""
        if policy_id in self._policies:
            del self._policies[policy_id]
    
    def get_applicable_policies(self, request: ApprovalRequest) -> List[ApprovalPolicy]:
        """Get policies that apply to a request"""
        applicable = []
        
        for policy in self._policies.values():
            if not policy.is_active:
                continue
            
            # Check organization match
            if policy.organization_id and policy.organization_id != request.context.organization_id:
                continue
            
            # Check workspace match
            if policy.workspace_ids and request.context.workspace_id not in policy.workspace_ids:
                continue
            
            # Check agent match
            if policy.agent_ids and request.context.agent_id not in policy.agent_ids:
                continue
            
            # Check action type match
            if policy.action_types and request.approval_type not in policy.action_types:
                continue
            
            # Check risk score
            if request.context.risk_score < policy.min_risk_score:
                continue
            
            # Check tool pattern match
            if policy.tool_patterns:
                import re
                tool_match = any(
                    re.match(pattern, request.context.tool_name)
                    for pattern in policy.tool_patterns
                )
                if not tool_match:
                    continue
            
            applicable.append(policy)
        
        # Sort by priority (higher first)
        applicable.sort(key=lambda p: -p.priority)
        
        return applicable
    
    def get_approvers(
        self,
        request: ApprovalRequest,
        escalation_level: int = 0
    ) -> List[str]:
        """Get list of approvers for a request"""
        approvers = set()
        
        policies = self.get_applicable_policies(request)
        
        for policy in policies:
            # Get from escalation chain if escalated
            if escalation_level > 0 and policy.escalation_chain:
                if escalation_level <= len(policy.escalation_chain):
                    approvers.update(policy.escalation_chain[escalation_level - 1])
            else:
                # Get from regular approvers
                approvers.update(policy.approver_users)
        
        # If no specific approvers, use default admin role
        if not approvers:
            approvers.add("admin")  # Fallback
        
        # Filter by availability if tracking
        available_approvers = [
            a for a in approvers
            if self._approver_availability.get(a, True)
        ]
        
        # Sort by load (least loaded first)
        available_approvers.sort(key=lambda a: self._approver_load.get(a, 0))
        
        return available_approvers
    
    def should_auto_approve(self, request: ApprovalRequest) -> bool:
        """Check if request should be auto-approved"""
        policies = self.get_applicable_policies(request)
        
        for policy in policies:
            threshold = policy.auto_approve_below_risk
            if threshold is None:
                threshold = DEFAULT_CONFIG.auto_approve_below_risk
            
            if request.context.risk_score < threshold:
                return True
        
        return False
    
    def should_auto_deny(self, request: ApprovalRequest) -> bool:
        """Check if request should be auto-denied"""
        policies = self.get_applicable_policies(request)
        
        for policy in policies:
            threshold = policy.auto_deny_above_risk
            if threshold is None:
                threshold = DEFAULT_CONFIG.auto_deny_above_risk
            
            if request.context.risk_score >= threshold:
                return True
        
        return False
    
    def update_approver_availability(self, user_id: str, available: bool):
        """Update approver availability"""
        self._approver_availability[user_id] = available
    
    def increment_approver_load(self, user_id: str):
        """Increment approver's pending request count"""
        self._approver_load[user_id] = self._approver_load.get(user_id, 0) + 1
    
    def decrement_approver_load(self, user_id: str):
        """Decrement approver's pending request count"""
        if user_id in self._approver_load:
            self._approver_load[user_id] = max(0, self._approver_load[user_id] - 1)


# =============================================================================
# RULE ENGINE
# =============================================================================

class ApprovalRuleEngine:
    """
    Manages pre-configured approval/denial rules
    
    Features:
    - Rule matching
    - Rule creation from approvals
    - Rule lifecycle management
    """
    
    def __init__(self):
        self._rules: Dict[str, ApprovalRule] = {}
    
    def add_rule(self, rule: ApprovalRule):
        """Add a rule"""
        self._rules[rule.id] = rule
        logger.info(f"Added approval rule: {rule.name} ({rule.rule_type})")
    
    def remove_rule(self, rule_id: str):
        """Remove a rule"""
        if rule_id in self._rules:
            del self._rules[rule_id]
    
    def create_rule_from_decision(
        self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        created_by: str
    ) -> Optional[ApprovalRule]:
        """Create a rule from an approval decision"""
        
        if decision == ApprovalDecision.APPROVE_ALWAYS:
            rule = ApprovalRule(
                name=f"Allow {request.context.tool_name} for {request.context.agent_name}",
                rule_type="allow",
                organization_id=request.context.organization_id,
                agent_id=request.context.agent_id,
                tool_name=request.context.tool_name,
                scope="always",
                created_by=created_by,
                created_from_request_id=request.id,
            )
            self.add_rule(rule)
            return rule
        
        elif decision == ApprovalDecision.DENY_ALWAYS:
            rule = ApprovalRule(
                name=f"Block {request.context.tool_name} for {request.context.agent_name}",
                rule_type="deny",
                organization_id=request.context.organization_id,
                agent_id=request.context.agent_id,
                tool_name=request.context.tool_name,
                scope="always",
                created_by=created_by,
                created_from_request_id=request.id,
            )
            self.add_rule(rule)
            return rule
        
        elif decision == ApprovalDecision.APPROVE_SESSION:
            rule = ApprovalRule(
                name=f"Allow {request.context.tool_name} for session",
                rule_type="allow",
                organization_id=request.context.organization_id,
                agent_id=request.context.agent_id,
                tool_name=request.context.tool_name,
                scope="session",
                session_id=request.context.session_id,
                created_by=created_by,
                created_from_request_id=request.id,
            )
            self.add_rule(rule)
            return rule
        
        return None
    
    def check_rules(self, context: ApprovalContext) -> Optional[Tuple[str, ApprovalRule]]:
        """
        Check if any rule matches the context
        
        Returns: (decision, rule) or None if no match
        """
        import re
        
        for rule in self._rules.values():
            if not rule.is_active:
                continue
            
            # Check expiration
            if rule.expires_at and datetime.utcnow() > rule.expires_at:
                rule.is_active = False
                continue
            
            # Check max uses
            if rule.max_uses > 0 and rule.use_count >= rule.max_uses:
                rule.is_active = False
                continue
            
            # Check organization
            if rule.organization_id and rule.organization_id != context.organization_id:
                continue
            
            # Check agent
            if rule.agent_id and rule.agent_id != context.agent_id:
                continue
            
            # Check tool
            if rule.tool_name and rule.tool_name != context.tool_name:
                continue
            
            # Check session scope
            if rule.scope == "session" and rule.session_id != context.session_id:
                continue
            
            # Check action pattern
            if rule.action_pattern:
                if not re.match(rule.action_pattern, context.action_type):
                    continue
            
            # Check parameter conditions
            if rule.parameter_conditions:
                params_match = all(
                    context.parameters.get(k) == v
                    for k, v in rule.parameter_conditions.items()
                )
                if not params_match:
                    continue
            
            # Rule matches!
            rule.use_count += 1
            
            return (rule.rule_type, rule)
        
        return None
    
    def get_rules(
        self,
        organization_id: str = None,
        agent_id: str = None,
        rule_type: str = None,
        is_active: bool = None
    ) -> List[ApprovalRule]:
        """Get rules with filters"""
        results = []
        
        for rule in self._rules.values():
            if organization_id and rule.organization_id != organization_id:
                continue
            if agent_id and rule.agent_id != agent_id:
                continue
            if rule_type and rule.rule_type != rule_type:
                continue
            if is_active is not None and rule.is_active != is_active:
                continue
            
            results.append(rule)
        
        return results


# =============================================================================
# HITL SERVICE
# =============================================================================

class HITLService:
    """
    Main Human-in-the-Loop service
    
    Features:
    - Request creation and management
    - Decision processing
    - Notification integration
    - Escalation handling
    - Audit logging
    """
    
    def __init__(
        self,
        config: HITLConfig = None,
        integration_manager = None
    ):
        self.config = config or DEFAULT_CONFIG
        self.integration_manager = integration_manager
        
        # Components
        self.router = ApprovalRouter()
        self.rule_engine = ApprovalRuleEngine()
        
        # Storage
        self._requests: Dict[str, ApprovalRequest] = {}
        self._audit_log: List[ApprovalAuditEntry] = []
        
        # Callbacks for async approval handling
        self._pending_callbacks: Dict[str, asyncio.Future] = {}
        
        # Running state
        self._running = False
    
    # =========================================================================
    # REQUEST LIFECYCLE
    # =========================================================================
    
    async def request_approval(
        self,
        context: ApprovalContext,
        approval_type: ApprovalType = ApprovalType.TOOL_EXECUTION,
        timeout_minutes: int = None,
        wait_for_decision: bool = True
    ) -> Tuple[ApprovalStatus, Optional[ApprovalRequest]]:
        """
        Request human approval for an action
        
        Args:
            context: Action context
            approval_type: Type of approval
            timeout_minutes: Custom timeout (or use default)
            wait_for_decision: If True, wait for decision before returning
            
        Returns:
            (status, request) - Status indicates the decision
        """
        # First check rules
        rule_result = self.rule_engine.check_rules(context)
        if rule_result:
            rule_type, rule = rule_result
            logger.info(f"Rule matched: {rule.name} -> {rule_type}")
            
            if rule_type == "allow":
                return ApprovalStatus.AUTO_APPROVED, None
            elif rule_type == "deny":
                return ApprovalStatus.AUTO_DENIED, None
        
        # Determine risk level
        risk_level = self._assess_risk_level(context)
        
        # Create request
        request = ApprovalRequest(
            approval_type=approval_type,
            risk_level=risk_level,
            title=self._generate_title(context),
            description=self._generate_description(context),
            context=context,
            requested_by=context.agent_id,
        )
        
        # Set custom timeout
        if timeout_minutes:
            request.expires_at = request.created_at + timedelta(minutes=timeout_minutes)
        
        # Check for auto-decision
        if self.config.enable_auto_approve:
            if self.router.should_auto_approve(request):
                request.status = ApprovalStatus.AUTO_APPROVED
                request.decision = ApprovalDecision.APPROVE
                request.decided_at = datetime.utcnow()
                request.decided_by = "system"
                self._log_audit(request, "auto_approved", "system", "system")
                return ApprovalStatus.AUTO_APPROVED, request
            
            if self.router.should_auto_deny(request):
                request.status = ApprovalStatus.AUTO_DENIED
                request.decision = ApprovalDecision.DENY
                request.decided_at = datetime.utcnow()
                request.decided_by = "system"
                self._log_audit(request, "auto_denied", "system", "system")
                return ApprovalStatus.AUTO_DENIED, request
        
        # Get approvers
        request.assigned_to = self.router.get_approvers(request)
        
        # Update approver load
        for approver in request.assigned_to:
            self.router.increment_approver_load(approver)
        
        # Store request
        self._requests[request.id] = request
        self._log_audit(request, "created", request.requested_by, "agent")
        
        logger.info(f"Created approval request {request.id}: {request.title}")
        
        # Send notifications
        await self._send_approval_notification(request)
        
        # Wait for decision if requested
        if wait_for_decision:
            future = asyncio.get_event_loop().create_future()
            self._pending_callbacks[request.id] = future
            
            try:
                # Wait with timeout
                timeout = (request.expires_at - datetime.utcnow()).total_seconds()
                await asyncio.wait_for(future, timeout=max(1, timeout))
                
                # Refresh request
                request = self._requests.get(request.id)
                return request.status, request
                
            except asyncio.TimeoutError:
                # Handle expiration
                request = self._requests.get(request.id)
                if request and request.status == ApprovalStatus.PENDING:
                    await self._handle_expiration(request)
                    request = self._requests.get(request.id)
                return request.status if request else ApprovalStatus.EXPIRED, request
        
        return ApprovalStatus.PENDING, request
    
    async def process_decision(
        self,
        request_id: str,
        decision: ApprovalDecision,
        decided_by: str,
        justification: str = "",
        conditions: List[str] = None
    ) -> Tuple[bool, str]:
        """
        Process a decision on an approval request
        
        Returns: (success, message)
        """
        request = self._requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        if request.status != ApprovalStatus.PENDING:
            return False, f"Request already {request.status.value}"
        
        # Validate justification if required
        if self.config.require_justification:
            if not justification or len(justification) < self.config.min_justification_length:
                return False, f"Justification required (min {self.config.min_justification_length} chars)"
        
        # Check if decider is authorized
        if request.assigned_to and decided_by not in request.assigned_to:
            # Allow if admin or escalation
            if decided_by != "admin":
                return False, "Not authorized to decide this request"
        
        # Process decision
        old_status = request.status
        
        if decision in [ApprovalDecision.APPROVE, ApprovalDecision.APPROVE_ONCE,
                        ApprovalDecision.APPROVE_SESSION, ApprovalDecision.APPROVE_ALWAYS]:
            request.status = ApprovalStatus.APPROVED
        elif decision in [ApprovalDecision.DENY, ApprovalDecision.DENY_ALWAYS]:
            request.status = ApprovalStatus.DENIED
        elif decision == ApprovalDecision.ESCALATE:
            return await self._escalate_request(request, decided_by, justification)
        elif decision == ApprovalDecision.REQUEST_INFO:
            # Add comment but don't change status
            self._log_audit(
                request, "info_requested", decided_by, "user",
                {"justification": justification}
            )
            return True, "Information requested"
        
        request.decision = decision
        request.decided_at = datetime.utcnow()
        request.decided_by = decided_by
        request.justification = justification
        request.conditions = conditions or []
        
        # Update approver load
        for approver in request.assigned_to:
            self.router.decrement_approver_load(approver)
        
        # Create rule if applicable
        rule = self.rule_engine.create_rule_from_decision(request, decision, decided_by)
        if rule:
            logger.info(f"Created rule from decision: {rule.name}")
        
        # Log audit
        self._log_audit(
            request, "decided", decided_by, "user",
            {
                "decision": decision.value,
                "justification": justification,
                "previous_status": old_status.value,
            }
        )
        
        logger.info(f"Request {request_id} decided: {decision.value} by {decided_by}")
        
        # Resolve waiting future
        if request_id in self._pending_callbacks:
            future = self._pending_callbacks.pop(request_id)
            if not future.done():
                future.set_result(request.status)
        
        # Send notification
        await self._send_decision_notification(request)
        
        return True, f"Request {decision.value}"
    
    async def _escalate_request(
        self,
        request: ApprovalRequest,
        escalated_by: str,
        reason: str
    ) -> Tuple[bool, str]:
        """Escalate a request to the next level"""
        if request.escalation_level >= self.config.max_escalation_levels:
            return False, "Maximum escalation level reached"
        
        old_level = request.escalation_level
        request.escalation_level += 1
        request.status = ApprovalStatus.ESCALATED
        
        # Get new approvers
        new_approvers = self.router.get_approvers(request, request.escalation_level)
        
        if not new_approvers:
            return False, "No approvers available at escalation level"
        
        # Update load
        for approver in request.assigned_to:
            self.router.decrement_approver_load(approver)
        
        request.assigned_to = new_approvers
        
        for approver in new_approvers:
            self.router.increment_approver_load(approver)
        
        # Extend timeout
        request.expires_at = datetime.utcnow() + timedelta(
            minutes=self.config.escalation_timeout_minutes
        )
        
        # Reset status to pending
        request.status = ApprovalStatus.PENDING
        
        # Log escalation
        request.escalation_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "from_level": old_level,
            "to_level": request.escalation_level,
            "escalated_by": escalated_by,
            "reason": reason,
            "new_approvers": new_approvers,
        })
        
        self._log_audit(
            request, "escalated", escalated_by, "user",
            {
                "from_level": old_level,
                "to_level": request.escalation_level,
                "reason": reason,
            }
        )
        
        logger.info(f"Request {request.id} escalated to level {request.escalation_level}")
        
        # Send escalation notification
        await self._send_escalation_notification(request)
        
        return True, f"Escalated to level {request.escalation_level}"
    
    async def _handle_expiration(self, request: ApprovalRequest):
        """Handle request expiration"""
        if request.status != ApprovalStatus.PENDING:
            return
        
        # Check if should auto-escalate
        if self.config.enable_auto_escalation:
            if request.escalation_level < self.config.max_escalation_levels:
                await self._escalate_request(request, "system", "Timeout auto-escalation")
                return
        
        # Expire the request
        request.status = ApprovalStatus.EXPIRED
        request.decided_at = datetime.utcnow()
        
        # Update approver load
        for approver in request.assigned_to:
            self.router.decrement_approver_load(approver)
        
        self._log_audit(request, "expired", "system", "system")
        
        logger.info(f"Request {request.id} expired")
        
        # Resolve waiting future
        if request.id in self._pending_callbacks:
            future = self._pending_callbacks.pop(request.id)
            if not future.done():
                future.set_result(ApprovalStatus.EXPIRED)
    
    def cancel_request(self, request_id: str, cancelled_by: str) -> bool:
        """Cancel a pending request"""
        request = self._requests.get(request_id)
        if not request or request.status != ApprovalStatus.PENDING:
            return False
        
        request.status = ApprovalStatus.CANCELLED
        request.decided_at = datetime.utcnow()
        request.decided_by = cancelled_by
        
        # Update approver load
        for approver in request.assigned_to:
            self.router.decrement_approver_load(approver)
        
        self._log_audit(request, "cancelled", cancelled_by, "user")
        
        # Resolve waiting future
        if request_id in self._pending_callbacks:
            future = self._pending_callbacks.pop(request_id)
            if not future.done():
                future.set_result(ApprovalStatus.CANCELLED)
        
        return True
    
    # =========================================================================
    # QUERY METHODS
    # =========================================================================
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get request by ID"""
        return self._requests.get(request_id)
    
    def get_request_by_token(self, token: str) -> Optional[ApprovalRequest]:
        """Get request by callback token"""
        for request in self._requests.values():
            if request.callback_token == token:
                return request
        return None
    
    def list_requests(
        self,
        organization_id: str = None,
        status: ApprovalStatus = None,
        assigned_to: str = None,
        agent_id: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[ApprovalRequest], int]:
        """List requests with filters"""
        results = []
        
        for request in self._requests.values():
            if organization_id and request.context.organization_id != organization_id:
                continue
            if status and request.status != status:
                continue
            if assigned_to and assigned_to not in request.assigned_to:
                continue
            if agent_id and request.context.agent_id != agent_id:
                continue
            
            results.append(request)
        
        # Sort by created_at (newest first)
        results.sort(key=lambda r: r.created_at, reverse=True)
        
        total = len(results)
        results = results[offset:offset + limit]
        
        return results, total
    
    def get_pending_for_user(self, user_id: str) -> List[ApprovalRequest]:
        """Get pending requests assigned to a user"""
        return [
            r for r in self._requests.values()
            if r.status == ApprovalStatus.PENDING and user_id in r.assigned_to
        ]
    
    def get_stats(self, organization_id: str = None, period_hours: int = 24) -> Dict[str, Any]:
        """Get approval statistics"""
        cutoff = datetime.utcnow() - timedelta(hours=period_hours)
        
        requests = [
            r for r in self._requests.values()
            if r.created_at >= cutoff
            and (not organization_id or r.context.organization_id == organization_id)
        ]
        
        stats = {
            "total_requests": len(requests),
            "by_status": {},
            "by_type": {},
            "by_risk_level": {},
            "avg_decision_time_seconds": 0,
            "auto_approved": 0,
            "auto_denied": 0,
            "escalated": 0,
            "expired": 0,
        }
        
        decision_times = []
        
        for request in requests:
            # By status
            status = request.status.value
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            
            # By type
            req_type = request.approval_type.value
            stats["by_type"][req_type] = stats["by_type"].get(req_type, 0) + 1
            
            # By risk level
            risk = request.risk_level.value
            stats["by_risk_level"][risk] = stats["by_risk_level"].get(risk, 0) + 1
            
            # Counters
            if request.status == ApprovalStatus.AUTO_APPROVED:
                stats["auto_approved"] += 1
            elif request.status == ApprovalStatus.AUTO_DENIED:
                stats["auto_denied"] += 1
            elif request.status == ApprovalStatus.EXPIRED:
                stats["expired"] += 1
            
            if request.escalation_level > 0:
                stats["escalated"] += 1
            
            # Decision time
            if request.decided_at and request.created_at:
                dt = (request.decided_at - request.created_at).total_seconds()
                decision_times.append(dt)
        
        if decision_times:
            stats["avg_decision_time_seconds"] = sum(decision_times) / len(decision_times)
        
        return stats
    
    # =========================================================================
    # BULK OPERATIONS
    # =========================================================================
    
    async def bulk_approve(
        self,
        request_ids: List[str],
        decided_by: str,
        justification: str
    ) -> Dict[str, Tuple[bool, str]]:
        """Bulk approve multiple requests"""
        if not self.config.bulk_approval_enabled:
            return {rid: (False, "Bulk approval disabled") for rid in request_ids}
        
        if len(request_ids) > self.config.bulk_approval_max_items:
            return {rid: (False, f"Max {self.config.bulk_approval_max_items} items") for rid in request_ids}
        
        results = {}
        
        for request_id in request_ids:
            success, message = await self.process_decision(
                request_id,
                ApprovalDecision.APPROVE,
                decided_by,
                f"[Bulk] {justification}"
            )
            results[request_id] = (success, message)
        
        return results
    
    async def bulk_deny(
        self,
        request_ids: List[str],
        decided_by: str,
        justification: str
    ) -> Dict[str, Tuple[bool, str]]:
        """Bulk deny multiple requests"""
        if not self.config.bulk_approval_enabled:
            return {rid: (False, "Bulk denial disabled") for rid in request_ids}
        
        results = {}
        
        for request_id in request_ids:
            success, message = await self.process_decision(
                request_id,
                ApprovalDecision.DENY,
                decided_by,
                f"[Bulk] {justification}"
            )
            results[request_id] = (success, message)
        
        return results
    
    # =========================================================================
    # NOTIFICATIONS
    # =========================================================================
    
    async def _send_approval_notification(self, request: ApprovalRequest):
        """Send notification for new approval request"""
        if not self.integration_manager:
            return
        
        try:
            from .integrations.integration_service import (
                Notification, NotificationType, NotificationPriority
            )
            
            priority_map = {
                RiskLevel.CRITICAL: NotificationPriority.CRITICAL,
                RiskLevel.HIGH: NotificationPriority.HIGH,
                RiskLevel.MEDIUM: NotificationPriority.MEDIUM,
                RiskLevel.LOW: NotificationPriority.LOW,
                RiskLevel.MINIMAL: NotificationPriority.INFO,
            }
            
            notification = Notification(
                id=request.id,
                notification_type=NotificationType.APPROVAL_REQUEST,
                priority=priority_map.get(request.risk_level, NotificationPriority.MEDIUM),
                title=f"🔐 Approval Required: {request.title}",
                message=request.description,
                details={
                    "Request ID": request.id[:8],
                    "Risk Score": f"{request.context.risk_score:.0f}/100",
                    "Risk Level": request.risk_level.value.upper(),
                    "Agent": request.context.agent_name or request.context.agent_id,
                    "Tool": request.context.tool_name,
                    "Expires": request.expires_at.strftime("%H:%M:%S UTC"),
                },
                actions=[
                    {"id": f"approve_{request.id}", "label": "✅ Approve", "type": "approve"},
                    {"id": f"deny_{request.id}", "label": "❌ Deny", "type": "deny", "style": "danger"},
                    {"id": f"investigate_{request.id}", "label": "🔍 Details", "type": "investigate"},
                ],
                organization_id=request.context.organization_id,
            )
            
            await self.integration_manager.send_notification(notification)
            
            request.notification_count += 1
            request.last_notification_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Failed to send approval notification: {e}")
    
    async def _send_decision_notification(self, request: ApprovalRequest):
        """Send notification about decision"""
        if not self.integration_manager:
            return
        
        try:
            from .integrations.integration_service import (
                Notification, NotificationType, NotificationPriority
            )
            
            decision_emoji = "✅" if request.status == ApprovalStatus.APPROVED else "❌"
            
            notification = Notification(
                notification_type=NotificationType.APPROVAL_RESPONSE,
                priority=NotificationPriority.INFO,
                title=f"{decision_emoji} Request {request.status.value}: {request.title}",
                message=f"Decided by {request.decided_by}: {request.justification}",
                details={
                    "Request ID": request.id[:8],
                    "Decision": request.decision.value if request.decision else "N/A",
                    "Decided By": request.decided_by,
                },
                organization_id=request.context.organization_id,
            )
            
            await self.integration_manager.send_notification(notification)
            
        except Exception as e:
            logger.error(f"Failed to send decision notification: {e}")
    
    async def _send_escalation_notification(self, request: ApprovalRequest):
        """Send notification about escalation"""
        if not self.integration_manager:
            return
        
        try:
            from .integrations.integration_service import (
                Notification, NotificationType, NotificationPriority
            )
            
            notification = Notification(
                id=request.id,
                notification_type=NotificationType.APPROVAL_REQUEST,
                priority=NotificationPriority.HIGH,
                title=f"⬆️ ESCALATED: {request.title}",
                message=f"Escalation Level {request.escalation_level}: {request.description}",
                details={
                    "Request ID": request.id[:8],
                    "Risk Score": f"{request.context.risk_score:.0f}/100",
                    "Escalation Level": request.escalation_level,
                    "Agent": request.context.agent_name,
                    "Tool": request.context.tool_name,
                },
                actions=[
                    {"id": f"approve_{request.id}", "label": "✅ Approve", "type": "approve"},
                    {"id": f"deny_{request.id}", "label": "❌ Deny", "type": "deny", "style": "danger"},
                ],
                organization_id=request.context.organization_id,
            )
            
            await self.integration_manager.send_notification(notification)
            
        except Exception as e:
            logger.error(f"Failed to send escalation notification: {e}")
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _assess_risk_level(self, context: ApprovalContext) -> RiskLevel:
        """Assess risk level from context"""
        risk_score = context.risk_score
        
        if risk_score >= 90:
            return RiskLevel.CRITICAL
        elif risk_score >= 70:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        elif risk_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _generate_title(self, context: ApprovalContext) -> str:
        """Generate request title"""
        return f"{context.agent_name or 'Agent'} wants to use {context.tool_name}"
    
    def _generate_description(self, context: ApprovalContext) -> str:
        """Generate request description"""
        lines = [
            f"Agent **{context.agent_name or context.agent_id}** is requesting approval to execute:",
            f"",
            f"**Tool:** {context.tool_name}",
            f"**Action:** {context.action_type}",
        ]
        
        if context.original_goal:
            lines.append(f"**Original Goal:** {context.original_goal}")
        
        if context.expected_outcome:
            lines.append(f"**Expected Outcome:** {context.expected_outcome}")
        
        if context.risk_factors:
            lines.append(f"**Risk Factors:** {', '.join(context.risk_factors)}")
        
        if context.violations:
            lines.append(f"**Policy Violations:** {', '.join(context.violations)}")
        
        if context.reasoning_chain:
            lines.append(f"\n**Agent Reasoning:**")
            for i, step in enumerate(context.reasoning_chain[-3:], 1):
                lines.append(f"  {i}. {step}")
        
        return "\n".join(lines)
    
    def _log_audit(
        self,
        request: ApprovalRequest,
        action: str,
        actor: str,
        actor_type: str,
        details: Dict = None
    ):
        """Log audit entry"""
        entry = ApprovalAuditEntry(
            request_id=request.id,
            action=action,
            actor=actor,
            actor_type=actor_type,
            previous_status=request.status.value,
            new_status=request.status.value,
            details=details or {},
        )
        self._audit_log.append(entry)
    
    def get_audit_log(
        self,
        request_id: str = None,
        limit: int = 100
    ) -> List[ApprovalAuditEntry]:
        """Get audit log entries"""
        entries = self._audit_log
        
        if request_id:
            entries = [e for e in entries if e.request_id == request_id]
        
        return entries[-limit:]
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    
    async def start(self):
        """Start the HITL service"""
        self._running = True
        asyncio.create_task(self._expiration_monitor())
        asyncio.create_task(self._reminder_task())
        logger.info("HITL Service started")
    
    async def stop(self):
        """Stop the HITL service"""
        self._running = False
        logger.info("HITL Service stopped")
    
    async def _expiration_monitor(self):
        """Monitor for expired requests"""
        while self._running:
            try:
                for request in list(self._requests.values()):
                    if request.is_expired():
                        await self._handle_expiration(request)
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Expiration monitor error: {e}")
                await asyncio.sleep(10)
    
    async def _reminder_task(self):
        """Send reminders for pending requests"""
        while self._running:
            try:
                now = datetime.utcnow()
                
                for request in self._requests.values():
                    if request.status != ApprovalStatus.PENDING:
                        continue
                    
                    if request.notification_count >= self.config.max_reminders:
                        continue
                    
                    if request.last_notification_at:
                        since_last = (now - request.last_notification_at).total_seconds() / 60
                        if since_last >= self.config.reminder_interval_minutes:
                            await self._send_approval_notification(request)
                
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Reminder task error: {e}")
                await asyncio.sleep(60)


# =============================================================================
# HITL DECORATOR FOR AGENT ACTIONS
# =============================================================================

def require_approval(
    approval_type: ApprovalType = ApprovalType.TOOL_EXECUTION,
    min_risk_score: float = 50.0,
    timeout_minutes: int = None
):
    """
    Decorator to require HITL approval for an action
    
    Usage:
        @require_approval(approval_type=ApprovalType.DATA_ACCESS, min_risk_score=70)
        async def access_database(query: str):
            ...
    """
    def decorator(func):
        async def wrapper(*args, hitl_service: HITLService = None, context: ApprovalContext = None, **kwargs):
            if not hitl_service or not context:
                # No HITL configured, execute directly
                return await func(*args, **kwargs)
            
            # Check if approval needed
            if context.risk_score < min_risk_score:
                return await func(*args, **kwargs)
            
            # Request approval
            status, request = await hitl_service.request_approval(
                context=context,
                approval_type=approval_type,
                timeout_minutes=timeout_minutes,
                wait_for_decision=True
            )
            
            if status in [ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED]:
                return await func(*args, **kwargs)
            else:
                raise PermissionError(f"Action denied: {status.value}")
        
        return wrapper
    return decorator


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    async def test_hitl():
        print("=" * 60)
        print("Testing HITL System")
        print("=" * 60)
        
        # Create HITL service
        config = HITLConfig(
            default_timeout_minutes=5,
            auto_approve_below_risk=25.0,
            auto_deny_above_risk=95.0,
        )
        
        hitl = HITLService(config=config)
        
        # Add approval policy
        print("\n📋 Adding approval policy...")
        policy = ApprovalPolicy(
            name="High-risk tool execution",
            organization_id="org-123",
            action_types=[ApprovalType.TOOL_EXECUTION, ApprovalType.DATA_ACCESS],
            min_risk_score=50.0,
            approver_users=["admin", "security-analyst"],
            escalation_chain=[
                ["team-lead"],
                ["security-manager"],
                ["ciso"],
            ],
        )
        hitl.router.add_policy(policy)
        print(f"  Added policy: {policy.name}")
        
        # Test auto-approve (low risk)
        print("\n✅ Testing auto-approve (risk=20)...")
        context1 = ApprovalContext(
            agent_id="agent-1",
            agent_name="helper-bot",
            organization_id="org-123",
            tool_name="calculator",
            action_type="calculate",
            risk_score=20.0,
        )
        
        status, request = await hitl.request_approval(context1, wait_for_decision=False)
        print(f"  Status: {status.value}")
        
        # Test auto-deny (very high risk)
        print("\n❌ Testing auto-deny (risk=98)...")
        context2 = ApprovalContext(
            agent_id="agent-1",
            agent_name="helper-bot",
            organization_id="org-123",
            tool_name="system_command",
            action_type="execute",
            risk_score=98.0,
            violations=["LLM01", "ASI05"],
        )
        
        status, request = await hitl.request_approval(context2, wait_for_decision=False)
        print(f"  Status: {status.value}")
        
        # Test pending approval
        print("\n⏳ Testing pending approval (risk=75)...")
        context3 = ApprovalContext(
            agent_id="agent-2",
            agent_name="data-analyst",
            organization_id="org-123",
            session_id="session-123",
            tool_name="database_query",
            action_type="read",
            parameters={"query": "SELECT * FROM users"},
            risk_score=75.0,
            risk_factors=["Broad query", "Sensitive table"],
            original_goal="Get user statistics",
            reasoning_chain=[
                "User asked for user count",
                "Need to query users table",
                "Constructed SELECT query",
            ],
        )
        
        status, request = await hitl.request_approval(context3, wait_for_decision=False)
        print(f"  Status: {status.value}")
        print(f"  Request ID: {request.id}")
        print(f"  Assigned to: {request.assigned_to}")
        print(f"  Expires at: {request.expires_at}")
        
        # Approve the request
        print("\n👍 Approving request...")
        success, message = await hitl.process_decision(
            request.id,
            ApprovalDecision.APPROVE_SESSION,
            "security-analyst",
            "Query looks safe, approved for this session"
        )
        print(f"  Result: {message}")
        
        # Check request status
        request = hitl.get_request(request.id)
        print(f"  Final status: {request.status.value}")
        print(f"  Decision: {request.decision.value}")
        
        # Check if rule was created
        print("\n📜 Checking rules...")
        rules = hitl.rule_engine.get_rules(organization_id="org-123")
        for rule in rules:
            print(f"  - {rule.name} ({rule.rule_type}, scope: {rule.scope})")
        
        # Test rule matching
        print("\n🔍 Testing rule matching...")
        context4 = ApprovalContext(
            agent_id="agent-2",
            agent_name="data-analyst",
            organization_id="org-123",
            session_id="session-123",  # Same session
            tool_name="database_query",
            action_type="read",
            risk_score=75.0,
        )
        
        rule_result = hitl.rule_engine.check_rules(context4)
        if rule_result:
            rule_type, rule = rule_result
            print(f"  Matched rule: {rule.name} -> {rule_type}")
        
        # Get statistics
        print("\n📊 Statistics:")
        stats = hitl.get_stats("org-123")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  By status: {stats['by_status']}")
        print(f"  Auto-approved: {stats['auto_approved']}")
        print(f"  Auto-denied: {stats['auto_denied']}")
        
        # Get audit log
        print("\n📝 Audit Log:")
        audit = hitl.get_audit_log(limit=5)
        for entry in audit[-3:]:
            print(f"  - {entry.action} by {entry.actor} ({entry.actor_type})")
        
        # Test denial
        print("\n🚫 Testing denial flow...")
        context5 = ApprovalContext(
            agent_id="agent-3",
            agent_name="rogue-bot",
            organization_id="org-123",
            tool_name="file_delete",
            action_type="delete",
            parameters={"path": "/important/data"},
            risk_score=85.0,
            violations=["ASI02"],
        )
        
        status, request = await hitl.request_approval(context5, wait_for_decision=False)
        print(f"  Created request: {request.id[:8]}")
        
        success, message = await hitl.process_decision(
            request.id,
            ApprovalDecision.DENY_ALWAYS,
            "admin",
            "This agent should never delete files"
        )
        print(f"  Denied: {message}")
        
        # Check deny rule
        rules = hitl.rule_engine.get_rules(rule_type="deny")
        print(f"  Deny rules: {len(rules)}")
        
        print("\n✅ HITL System tests complete!")
    
    asyncio.run(test_hitl())

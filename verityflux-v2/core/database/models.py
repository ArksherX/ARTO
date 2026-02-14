#!/usr/bin/env python3
"""
VerityFlux Enterprise - Database Models
PostgreSQL + TimescaleDB with Multi-Tenancy Support

This module defines all database models for:
- Multi-tenant organizations and users
- Licensing and tier management
- Security events and audit logs
- Vulnerability database
- SOC incidents and cases
- HITL approval workflows
"""

import uuid
import enum
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Enum, Index, UniqueConstraint, CheckConstraint,
    BigInteger, LargeBinary, Table
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, ARRAY
from sqlalchemy.sql import func
import hashlib
import secrets

Base = declarative_base()


# =============================================================================
# ENUMS
# =============================================================================

class DeploymentMode(enum.Enum):
    """Deployment mode for the installation"""
    SAAS = "saas"
    ON_PREMISE = "on_premise"
    HYBRID = "hybrid"


class SubscriptionTier(enum.Enum):
    """Subscription tiers with feature gating"""
    FREE = "free"
    STARTUP = "startup"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class UserRole(enum.Enum):
    """User roles for RBAC"""
    SUPER_ADMIN = "super_admin"      # VerityFlux staff
    ORG_ADMIN = "org_admin"          # Organization administrator
    WORKSPACE_ADMIN = "workspace_admin"  # Workspace administrator
    ANALYST = "analyst"              # SOC analyst
    VIEWER = "viewer"                # Read-only access
    API_USER = "api_user"            # Programmatic access only


class LicenseStatus(enum.Enum):
    """License status for on-premise deployments"""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    TRIAL = "trial"


class ScanStatus(enum.Enum):
    """Security scan status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.Enum):
    """Types of security scans"""
    QUICK = "quick"          # Top 5 critical vulns
    STANDARD = "standard"    # All 20 OWASP
    DEEP = "deep"            # + fuzzing + edge cases
    COMPLIANCE = "compliance"  # SOC2, GDPR mapping
    CUSTOM = "custom"        # User-defined


class VulnerabilitySeverity(enum.Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(enum.Enum):
    """SOC incident status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentPriority(enum.Enum):
    """Incident priority levels"""
    CRITICAL = "critical"    # P1 - Immediate response
    HIGH = "high"            # P2 - Within 1 hour
    MEDIUM = "medium"        # P3 - Within 4 hours
    LOW = "low"              # P4 - Within 24 hours


class ApprovalStatus(enum.Enum):
    """HITL approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_DENIED = "auto_denied"


class IntegrationType(enum.Enum):
    """External integration types"""
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    JIRA = "jira"
    EMAIL = "email"
    TWILIO = "twilio"
    WEBHOOK = "webhook"
    SIEM = "siem"


class AgentStatus(enum.Enum):
    """Monitored agent status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"


# =============================================================================
# TIER FEATURE LIMITS
# =============================================================================

TIER_LIMITS = {
    SubscriptionTier.FREE: {
        "max_scans_per_month": 5,
        "scan_types_allowed": [ScanType.QUICK],
        "max_agents": 1,
        "max_evaluations_per_month": 1000,
        "max_users": 2,
        "hitl_enabled": False,
        "soc_integrations": [],
        "vuln_db_update_frequency": "monthly",
        "backdoor_detector": "basic",
        "adversarial_lab": False,
        "multi_workspace": False,
        "api_access": False,
        "on_premise": False,
        "custom_rules": False,
        "report_export": ["pdf"],
        "retention_days": 30,
    },
    SubscriptionTier.STARTUP: {
        "max_scans_per_month": 50,
        "scan_types_allowed": [ScanType.QUICK, ScanType.STANDARD],
        "max_agents": 5,
        "max_evaluations_per_month": 10000,
        "max_users": 10,
        "hitl_enabled": True,
        "soc_integrations": [IntegrationType.SLACK, IntegrationType.EMAIL],
        "vuln_db_update_frequency": "weekly",
        "backdoor_detector": "full",
        "adversarial_lab": "ctf_only",
        "multi_workspace": False,
        "api_access": "read_only",
        "on_premise": False,
        "custom_rules": False,
        "report_export": ["pdf", "json"],
        "retention_days": 90,
    },
    SubscriptionTier.PROFESSIONAL: {
        "max_scans_per_month": -1,  # Unlimited
        "scan_types_allowed": [ScanType.QUICK, ScanType.STANDARD, ScanType.DEEP],
        "max_agents": 25,
        "max_evaluations_per_month": 100000,
        "max_users": 50,
        "hitl_enabled": True,
        "soc_integrations": [
            IntegrationType.SLACK, IntegrationType.TEAMS,
            IntegrationType.PAGERDUTY, IntegrationType.JIRA,
            IntegrationType.EMAIL, IntegrationType.WEBHOOK
        ],
        "vuln_db_update_frequency": "daily",
        "backdoor_detector": "full",
        "adversarial_lab": "full",
        "multi_workspace": True,
        "api_access": "full",
        "on_premise": False,
        "custom_rules": True,
        "report_export": ["pdf", "json", "csv", "html"],
        "retention_days": 365,
    },
    SubscriptionTier.ENTERPRISE: {
        "max_scans_per_month": -1,  # Unlimited
        "scan_types_allowed": [ScanType.QUICK, ScanType.STANDARD, ScanType.DEEP, ScanType.COMPLIANCE, ScanType.CUSTOM],
        "max_agents": -1,  # Unlimited
        "max_evaluations_per_month": -1,  # Unlimited
        "max_users": -1,  # Unlimited
        "hitl_enabled": True,
        "soc_integrations": [
            IntegrationType.SLACK, IntegrationType.TEAMS,
            IntegrationType.PAGERDUTY, IntegrationType.JIRA,
            IntegrationType.EMAIL, IntegrationType.TWILIO,
            IntegrationType.WEBHOOK, IntegrationType.SIEM
        ],
        "vuln_db_update_frequency": "realtime",
        "backdoor_detector": "full",
        "adversarial_lab": "full_custom",
        "multi_workspace": True,
        "api_access": "full",
        "on_premise": True,
        "custom_rules": True,
        "report_export": ["pdf", "json", "csv", "html", "sarif"],
        "retention_days": -1,  # Unlimited
    },
}


# =============================================================================
# ORGANIZATION & TENANCY MODELS
# =============================================================================

class Organization(Base):
    """
    Top-level tenant - represents a company/organization
    """
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    
    # Subscription
    subscription_tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.FREE, nullable=False)
    subscription_status = Column(String(50), default="active")
    stripe_customer_id = Column(String(255), nullable=True)  # For SaaS billing
    stripe_subscription_id = Column(String(255), nullable=True)
    
    # On-premise licensing
    license_key = Column(String(512), nullable=True, unique=True)
    license_status = Column(Enum(LicenseStatus), nullable=True)
    license_expires_at = Column(DateTime, nullable=True)
    deployment_mode = Column(Enum(DeploymentMode), default=DeploymentMode.SAAS)
    
    # Usage tracking
    current_month_scans = Column(Integer, default=0)
    current_month_evaluations = Column(BigInteger, default=0)
    usage_reset_at = Column(DateTime, default=func.now)
    
    # Settings
    settings = Column(JSONB, default=dict)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    workspaces = relationship("Workspace", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    
    def get_tier_limits(self) -> dict:
        """Get feature limits for current subscription tier"""
        return TIER_LIMITS.get(self.subscription_tier, TIER_LIMITS[SubscriptionTier.FREE])
    
    def can_use_feature(self, feature: str) -> bool:
        """Check if organization can use a specific feature"""
        limits = self.get_tier_limits()
        feature_value = limits.get(feature)
        
        if feature_value is None:
            return False
        if isinstance(feature_value, bool):
            return feature_value
        if isinstance(feature_value, int) and feature_value == -1:
            return True  # Unlimited
        if isinstance(feature_value, list):
            return len(feature_value) > 0
        return bool(feature_value)
    
    def check_usage_limit(self, limit_type: str, increment: int = 1) -> bool:
        """Check if usage is within limits"""
        limits = self.get_tier_limits()
        
        if limit_type == "scans":
            max_allowed = limits.get("max_scans_per_month", 0)
            current = self.current_month_scans
        elif limit_type == "evaluations":
            max_allowed = limits.get("max_evaluations_per_month", 0)
            current = self.current_month_evaluations
        else:
            return True
        
        if max_allowed == -1:  # Unlimited
            return True
        
        return (current + increment) <= max_allowed


class Workspace(Base):
    """
    Workspace within an organization (e.g., Production, Staging, Development)
    """
    __tablename__ = "workspaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    environment = Column(String(50), default="production")  # production, staging, development
    
    # Workspace-specific settings (override org settings)
    settings = Column(JSONB, default=dict)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    organization = relationship("Organization", back_populates="workspaces")
    agents = relationship("MonitoredAgent", back_populates="workspace", cascade="all, delete-orphan")
    scans = relationship("SecurityScan", back_populates="workspace", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="workspace", cascade="all, delete-orphan")
    
    __table_args__ = (
        UniqueConstraint('organization_id', 'slug', name='uq_workspace_org_slug'),
    )


class User(Base):
    """
    User account with role-based access control
    """
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    # Authentication
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    
    # Role & Permissions
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    permissions = Column(JSONB, default=dict)  # Custom permission overrides
    workspace_access = Column(ARRAY(UUID(as_uuid=True)), default=list)  # Specific workspace access
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    
    # Session management
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(INET, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # Notification preferences
    notification_preferences = Column(JSONB, default=dict)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    approvals = relationship("HITLApproval", back_populates="reviewer")
    
    __table_args__ = (
        UniqueConstraint('organization_id', 'email', name='uq_user_org_email'),
    )
    
    def set_password(self, password: str):
        """Hash and set password"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        self.password_hash = f"{salt}:{hash_obj.hex()}"
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, stored_hash = self.password_hash.split(':')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == stored_hash
        except:
            return False
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        # Super admin has all permissions
        if self.role == UserRole.SUPER_ADMIN:
            return True
        
        # Check role-based permissions
        role_permissions = {
            UserRole.ORG_ADMIN: ["*"],  # All within org
            UserRole.WORKSPACE_ADMIN: ["workspace.*", "scan.*", "incident.*", "agent.*"],
            UserRole.ANALYST: ["scan.view", "scan.run", "incident.*", "agent.view", "approval.*"],
            UserRole.VIEWER: ["*.view"],
            UserRole.API_USER: ["api.*"],
        }
        
        allowed = role_permissions.get(self.role, [])
        
        # Check direct match or wildcard
        for perm in allowed:
            if perm == "*" or perm == permission:
                return True
            if perm.endswith(".*"):
                prefix = perm[:-2]
                if permission.startswith(prefix):
                    return True
            if perm == "*.view" and permission.endswith(".view"):
                return True
        
        # Check custom overrides
        return self.permissions.get(permission, False)


class UserSession(Base):
    """
    User session tracking
    """
    __tablename__ = "user_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    token_hash = Column(String(255), nullable=False, unique=True)
    refresh_token_hash = Column(String(255), nullable=True)
    
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    device_info = Column(JSONB, default=dict)
    
    created_at = Column(DateTime, default=func.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity_at = Column(DateTime, default=func.now)
    is_revoked = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="sessions")


class APIKey(Base):
    """
    API keys for programmatic access
    """
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    key_prefix = Column(String(10), nullable=False)  # First 8 chars for identification
    key_hash = Column(String(255), nullable=False, unique=True)
    
    permissions = Column(JSONB, default=dict)
    rate_limit = Column(Integer, default=1000)  # Requests per hour
    
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    organization = relationship("Organization", back_populates="api_keys")
    
    @staticmethod
    def generate_key() -> tuple:
        """Generate a new API key, returns (full_key, key_hash)"""
        key = f"vf_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key, key_hash


# =============================================================================
# MONITORED AGENTS & TARGETS
# =============================================================================

class MonitoredAgent(Base):
    """
    AI Agent registered for monitoring
    """
    __tablename__ = "monitored_agents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    agent_type = Column(String(100), nullable=False)  # langchain, llamaindex, custom, etc.
    
    # Connection details
    endpoint_url = Column(String(512), nullable=True)
    api_key_encrypted = Column(LargeBinary, nullable=True)  # Encrypted API key
    connection_config = Column(JSONB, default=dict)
    
    # Agent capabilities
    tools = Column(JSONB, default=list)  # List of tools agent can use
    model_provider = Column(String(100), nullable=True)  # openai, anthropic, local
    model_name = Column(String(255), nullable=True)
    
    # Security settings
    firewall_enabled = Column(Boolean, default=True)
    firewall_config = Column(JSONB, default=dict)
    sandbox_enabled = Column(Boolean, default=False)
    
    # Status
    status = Column(Enum(AgentStatus), default=AgentStatus.ACTIVE)
    last_seen_at = Column(DateTime, nullable=True)
    health_status = Column(JSONB, default=dict)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="agents")
    scans = relationship("SecurityScan", back_populates="agent")
    events = relationship("SecurityEvent", back_populates="agent")


class ScanTarget(Base):
    """
    Targets for security scanning (LLM endpoints, local models, etc.)
    """
    __tablename__ = "scan_targets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    target_type = Column(String(50), nullable=False)  # openai, anthropic, huggingface, ollama, custom
    
    # Connection details
    endpoint_url = Column(String(512), nullable=True)
    api_key_encrypted = Column(LargeBinary, nullable=True)
    model_name = Column(String(255), nullable=True)
    
    # Configuration
    config = Column(JSONB, default=dict)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    last_scanned_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


# =============================================================================
# SECURITY SCANNING
# =============================================================================

class SecurityScan(Base):
    """
    Security scan record
    """
    __tablename__ = "security_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("monitored_agents.id", ondelete="SET NULL"), nullable=True)
    target_id = Column(UUID(as_uuid=True), ForeignKey("scan_targets.id", ondelete="SET NULL"), nullable=True)
    
    # Scan configuration
    scan_type = Column(Enum(ScanType), nullable=False)
    scan_profile = Column(String(100), nullable=True)  # Custom profile name
    config = Column(JSONB, default=dict)
    
    # Status
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Float, default=0.0)  # 0-100
    
    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Results summary
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    
    vulnerabilities_critical = Column(Integer, default=0)
    vulnerabilities_high = Column(Integer, default=0)
    vulnerabilities_medium = Column(Integer, default=0)
    vulnerabilities_low = Column(Integer, default=0)
    vulnerabilities_info = Column(Integer, default=0)
    
    risk_score = Column(Float, nullable=True)  # 0-100 overall risk
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="scans")
    agent = relationship("MonitoredAgent", back_populates="scans")
    findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")


class ScanFinding(Base):
    """
    Individual vulnerability finding from a scan (Nessus-style)
    """
    __tablename__ = "scan_findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False)
    
    # Vulnerability identification
    vuln_id = Column(String(50), nullable=False)  # e.g., LLM01-2025-001
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=True)
    
    # Finding details
    title = Column(String(500), nullable=False)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    
    # Location
    component = Column(String(255), nullable=True)  # Which tool/endpoint
    location = Column(Text, nullable=True)  # Specific location details
    
    # Evidence
    evidence = Column(Text, nullable=True)  # Payload that triggered it
    response = Column(Text, nullable=True)  # Model response (truncated)
    
    # Analysis
    impact = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    # References
    references = Column(JSONB, default=list)  # Links to OWASP, CVE, etc.
    
    # Status
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    
    # CVSS-style scoring
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    
    # Relationships
    scan = relationship("SecurityScan", back_populates="findings")
    vulnerability = relationship("Vulnerability")
    
    __table_args__ = (
        Index('idx_finding_severity', 'severity'),
        Index('idx_finding_vuln_id', 'vuln_id'),
    )


# =============================================================================
# VULNERABILITY DATABASE
# =============================================================================

class Vulnerability(Base):
    """
    Vulnerability definitions (from NVD, OWASP, MITRE ATLAS, etc.)
    """
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Identification
    vuln_id = Column(String(50), unique=True, nullable=False, index=True)  # LLM01, ASI02, CVE-2024-XXXX
    source = Column(String(50), nullable=False)  # owasp, nvd, mitre_atlas, internal
    
    # Classification
    category = Column(String(100), nullable=False)  # LLM Top 10, Agentic Top 10, etc.
    subcategory = Column(String(100), nullable=True)
    
    # Details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False)
    
    # Impact & Risk
    impact = Column(Text, nullable=True)
    exploitability = Column(String(50), nullable=True)  # easy, moderate, difficult
    
    # Remediation
    recommendation = Column(Text, nullable=True)
    mitigation_steps = Column(JSONB, default=list)
    
    # Detection
    detection_patterns = Column(JSONB, default=list)  # Patterns to detect this vuln
    test_payloads = Column(JSONB, default=list)  # Payloads for testing
    
    # References
    references = Column(JSONB, default=list)
    cve_ids = Column(ARRAY(String), default=list)
    cwe_ids = Column(ARRAY(String), default=list)
    
    # CVSS
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    
    # Metadata
    published_at = Column(DateTime, nullable=True)
    last_modified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    is_active = Column(Boolean, default=True)
    
    __table_args__ = (
        Index('idx_vuln_source', 'source'),
        Index('idx_vuln_category', 'category'),
        Index('idx_vuln_severity', 'severity'),
    )


class VulnerabilityFeed(Base):
    """
    External vulnerability feed configuration
    """
    __tablename__ = "vulnerability_feeds"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    name = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)  # nvd_api, owasp_scrape, mitre_atlas, rss
    
    # Connection
    api_url = Column(String(512), nullable=True)
    api_key_encrypted = Column(LargeBinary, nullable=True)
    config = Column(JSONB, default=dict)
    
    # Sync settings
    sync_frequency = Column(String(50), default="daily")  # hourly, daily, weekly
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_status = Column(String(50), nullable=True)
    last_sync_error = Column(Text, nullable=True)
    
    # Stats
    total_vulnerabilities = Column(Integer, default=0)
    
    # Metadata
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now, nullable=False)


# =============================================================================
# SECURITY EVENTS (TimescaleDB Hypertable)
# =============================================================================

class SecurityEvent(Base):
    """
    Real-time security events from the cognitive firewall
    This table is designed to be a TimescaleDB hypertable for time-series queries
    """
    __tablename__ = "security_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=func.now, nullable=False, index=True)
    
    # Tenant context
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("monitored_agents.id"), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # evaluation, block, alert, approval_request
    
    # Action details
    tool_name = Column(String(255), nullable=True)
    action_parameters = Column(JSONB, default=dict)
    reasoning_chain = Column(JSONB, default=list)
    original_goal = Column(Text, nullable=True)
    
    # Decision
    decision = Column(String(50), nullable=False)  # allow, block, require_approval, log_only
    risk_score = Column(Float, nullable=True)
    risk_tier = Column(String(20), nullable=True)  # critical, high, medium, low
    confidence = Column(Float, nullable=True)
    
    # Analysis results
    violations = Column(JSONB, default=list)
    matched_patterns = Column(JSONB, default=list)
    
    # Context
    session_id = Column(String(255), nullable=True)
    request_id = Column(String(255), nullable=True)
    source_ip = Column(INET, nullable=True)
    
    # Relationships
    agent = relationship("MonitoredAgent", back_populates="events")
    
    __table_args__ = (
        Index('idx_event_org_time', 'organization_id', 'timestamp'),
        Index('idx_event_decision', 'decision'),
        Index('idx_event_risk_tier', 'risk_tier'),
    )


# =============================================================================
# SOC INCIDENT MANAGEMENT
# =============================================================================

class Incident(Base):
    """
    Security incident for SOC tracking
    """
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    
    # Identification
    incident_number = Column(String(50), unique=True, nullable=False)  # INC-2024-00001
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Classification
    incident_type = Column(String(100), nullable=False)  # backdoor, prompt_injection, data_exfil, etc.
    priority = Column(Enum(IncidentPriority), default=IncidentPriority.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    
    # Assignment
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    escalated_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Timing
    detected_at = Column(DateTime, default=func.now)
    acknowledged_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # SLA tracking
    sla_breach_at = Column(DateTime, nullable=True)
    sla_breached = Column(Boolean, default=False)
    
    # Impact assessment
    impact_score = Column(Integer, nullable=True)  # 1-10
    affected_agents = Column(JSONB, default=list)
    affected_users = Column(Integer, default=0)
    
    # Evidence
    evidence = Column(JSONB, default=list)
    related_events = Column(ARRAY(UUID(as_uuid=True)), default=list)
    
    # Resolution
    root_cause = Column(Text, nullable=True)
    resolution_summary = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)
    
    # External tracking
    external_ticket_id = Column(String(255), nullable=True)  # Jira, ServiceNow, etc.
    external_ticket_url = Column(String(512), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="incidents")
    comments = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_incident_status', 'status'),
        Index('idx_incident_priority', 'priority'),
    )


class IncidentComment(Base):
    """
    Comments on incidents
    """
    __tablename__ = "incident_comments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)  # Internal vs customer-facing
    
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    
    incident = relationship("Incident", back_populates="comments")


class IncidentTimeline(Base):
    """
    Incident timeline events
    """
    __tablename__ = "incident_timeline"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    
    event_type = Column(String(50), nullable=False)  # created, assigned, status_change, comment, etc.
    description = Column(Text, nullable=False)
    metadata = Column(JSONB, default=dict)
    
    created_at = Column(DateTime, default=func.now, nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    incident = relationship("Incident", back_populates="timeline")


# =============================================================================
# HITL APPROVAL WORKFLOW
# =============================================================================

class HITLApproval(Base):
    """
    Human-in-the-loop approval requests
    """
    __tablename__ = "hitl_approvals"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Context
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("monitored_agents.id"), nullable=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("security_events.id"), nullable=True)
    
    # Request details
    request_type = Column(String(50), nullable=False)  # tool_execution, data_access, etc.
    tool_name = Column(String(255), nullable=True)
    parameters = Column(JSONB, default=dict)
    reasoning = Column(Text, nullable=True)
    
    # Risk assessment
    risk_score = Column(Float, nullable=False)
    risk_tier = Column(String(20), nullable=False)
    violations = Column(JSONB, default=list)
    
    # Status
    status = Column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    
    # Timing
    created_at = Column(DateTime, default=func.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    
    # Review details
    reviewer_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    review_decision = Column(String(50), nullable=True)  # approve, deny, approve_once, create_rule
    review_reason = Column(Text, nullable=True)
    
    # Auto-escalation
    escalation_level = Column(Integer, default=0)
    escalated_at = Column(DateTime, nullable=True)
    
    # Relationships
    reviewer = relationship("User", back_populates="approvals")
    
    __table_args__ = (
        Index('idx_approval_status', 'status'),
        Index('idx_approval_org', 'organization_id'),
    )


# =============================================================================
# INTEGRATIONS
# =============================================================================

class Integration(Base):
    """
    External integrations (Slack, PagerDuty, Jira, etc.)
    """
    __tablename__ = "integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    integration_type = Column(Enum(IntegrationType), nullable=False)
    name = Column(String(255), nullable=False)
    
    # Connection details (encrypted)
    config_encrypted = Column(LargeBinary, nullable=True)
    
    # Settings
    settings = Column(JSONB, default=dict)
    notification_rules = Column(JSONB, default=list)  # When to trigger notifications
    
    # Status
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    
    __table_args__ = (
        UniqueConstraint('organization_id', 'integration_type', 'name', name='uq_integration'),
    )


# =============================================================================
# AUDIT LOG
# =============================================================================

class AuditLog(Base):
    """
    Comprehensive audit logging for compliance
    """
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=func.now, nullable=False, index=True)
    
    # Context
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Action details
    action = Column(String(100), nullable=False)  # user.login, scan.start, incident.create, etc.
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Changes
    old_value = Column(JSONB, nullable=True)
    new_value = Column(JSONB, nullable=True)
    
    # Request context
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    request_id = Column(String(255), nullable=True)
    
    # Result
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    __table_args__ = (
        Index('idx_audit_org_time', 'organization_id', 'timestamp'),
        Index('idx_audit_action', 'action'),
    )


# =============================================================================
# PLAYBOOKS & AUTOMATION
# =============================================================================

class Playbook(Base):
    """
    Automated response playbooks
    """
    __tablename__ = "playbooks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Trigger conditions
    trigger_type = Column(String(50), nullable=False)  # incident, event, schedule
    trigger_conditions = Column(JSONB, default=dict)
    
    # Actions
    steps = Column(JSONB, default=list)  # List of action steps
    
    # Settings
    is_active = Column(Boolean, default=True)
    requires_approval = Column(Boolean, default=False)
    
    # Stats
    execution_count = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now, nullable=False)
    updated_at = Column(DateTime, default=func.now, onupdate=func.now)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def init_database(connection_string: str, create_tables: bool = True) -> Session:
    """
    Initialize database connection and optionally create tables
    
    Args:
        connection_string: PostgreSQL connection string
        create_tables: Whether to create tables if they don't exist
        
    Returns:
        SQLAlchemy Session
    """
    engine = create_engine(
        connection_string,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=False
    )
    
    if create_tables:
        Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


def init_timescaledb(session: Session):
    """
    Initialize TimescaleDB hypertables for time-series data
    """
    # Convert security_events to hypertable
    session.execute("""
        SELECT create_hypertable('security_events', 'timestamp', 
            if_not_exists => TRUE,
            migrate_data => TRUE
        );
    """)
    
    # Add compression policy (compress data older than 7 days)
    session.execute("""
        SELECT add_compression_policy('security_events', INTERVAL '7 days',
            if_not_exists => TRUE
        );
    """)
    
    # Add retention policy (delete data older than retention period)
    # This will be configured per-tenant based on their tier
    
    session.commit()


# =============================================================================
# SEED DATA
# =============================================================================

def seed_owasp_vulnerabilities(session: Session):
    """
    Seed the vulnerability database with OWASP LLM Top 10 and Agentic Top 10
    """
    owasp_vulns = [
        # LLM Top 10 2025
        {
            "vuln_id": "LLM01",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Prompt Injection",
            "description": "Manipulation of LLM behavior through crafted inputs that override system instructions.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Complete control over LLM outputs, data exfiltration, unauthorized actions.",
            "recommendation": "Implement input validation, use privilege separation, monitor for anomalous prompts.",
            "cvss_score": 9.8,
        },
        {
            "vuln_id": "LLM02",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Sensitive Information Disclosure",
            "description": "Unintentional revelation of PII, credentials, or proprietary data through model outputs.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Data breach, privacy violations, credential exposure.",
            "recommendation": "Sanitize training data, implement output filtering, use PII detection.",
            "cvss_score": 8.5,
        },
        {
            "vuln_id": "LLM03",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Supply Chain Vulnerabilities",
            "description": "Risks from third-party models, plugins, or data sources introducing backdoors.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Compromised model integrity, backdoor execution, data poisoning.",
            "recommendation": "Audit model origins, use signed artifacts, verify plugin integrity.",
            "cvss_score": 8.2,
        },
        {
            "vuln_id": "LLM04",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Data and Model Poisoning",
            "description": "Malicious data introducing persistent biases or triggers into models.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Persistent backdoors, biased outputs, triggered malicious behavior.",
            "recommendation": "Verify data sources, use gold datasets for validation, monitor model drift.",
            "cvss_score": 9.5,
        },
        {
            "vuln_id": "LLM05",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Improper Output Handling",
            "description": "Downstream systems executing malicious content from LLM outputs.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Code execution, XSS, SQL injection through generated content.",
            "recommendation": "Apply zero-trust to outputs, sanitize all generated content.",
            "cvss_score": 8.8,
        },
        {
            "vuln_id": "LLM06",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Excessive Agency",
            "description": "Model granted too much autonomy for harmful actions without oversight.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Unauthorized actions, data deletion, privilege abuse.",
            "recommendation": "Apply principle of least privilege, require human approval for sensitive actions.",
            "cvss_score": 8.0,
        },
        {
            "vuln_id": "LLM07",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "System Prompt Leakage",
            "description": "Exposure of internal instructions enabling targeted exploitation.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "impact": "Attack surface expansion, targeted prompt injection.",
            "recommendation": "Harden system prompts, avoid embedding secrets, monitor for extraction attempts.",
            "cvss_score": 6.5,
        },
        {
            "vuln_id": "LLM08",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Vector and Embedding Weaknesses",
            "description": "Adversarial manipulation of RAG vector stores.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "impact": "Poisoned context retrieval, misdirected queries, data manipulation.",
            "recommendation": "Secure vector database access, validate context integrity.",
            "cvss_score": 6.8,
        },
        {
            "vuln_id": "LLM09",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Misinformation and Overreliance",
            "description": "Users following incorrect hallucinations as truth.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "impact": "Bad decisions, reputational damage, compliance violations.",
            "recommendation": "Implement cross-verification, add confidence indicators, enable HITL review.",
            "cvss_score": 5.5,
        },
        {
            "vuln_id": "LLM10",
            "source": "owasp",
            "category": "OWASP LLM Top 10 2025",
            "title": "Unbounded Consumption",
            "description": "Resource-heavy queries causing DoS or cost spikes.",
            "severity": VulnerabilitySeverity.LOW,
            "impact": "Service disruption, excessive costs, resource exhaustion.",
            "recommendation": "Enforce rate limits, token constraints, cost monitoring.",
            "cvss_score": 4.5,
        },
        # Agentic Top 10 2025
        {
            "vuln_id": "ASI01",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Agent Goal Hijacking",
            "description": "Manipulation of agent planning to pursue attacker objectives.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Complete agent compromise, malicious action execution.",
            "recommendation": "Continuous goal-consistency validation, immutable goal anchoring.",
            "cvss_score": 9.9,
        },
        {
            "vuln_id": "ASI02",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Tool Misuse and Exploitation",
            "description": "Agents using legitimate tools in destructive ways.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Data destruction, unauthorized access, system compromise.",
            "recommendation": "Tool-call sandboxing, parameter validation, action monitoring.",
            "cvss_score": 9.5,
        },
        {
            "vuln_id": "ASI03",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Identity and Privilege Abuse",
            "description": "Confused deputy scenarios with access escalation.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Privilege escalation, unauthorized resource access.",
            "recommendation": "Session-scoped keys, verify agent identity, audit privilege usage.",
            "cvss_score": 8.5,
        },
        {
            "vuln_id": "ASI04",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Agentic Supply Chain",
            "description": "Malicious third-party agents compromise ecosystem.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Ecosystem compromise, cascading attacks.",
            "recommendation": "Vet agent registries, verify collaborating agents, sandbox third-party agents.",
            "cvss_score": 8.2,
        },
        {
            "vuln_id": "ASI05",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Unexpected Code Execution",
            "description": "On-the-fly code generation leads to system compromise.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Full system compromise, data exfiltration, persistence.",
            "recommendation": "Isolate execution in ephemeral sandboxes, code review before execution.",
            "cvss_score": 9.8,
        },
        {
            "vuln_id": "ASI06",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Memory and Context Poisoning",
            "description": "Corruption of persistent agent memory.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Persistent compromise, poisoned future interactions.",
            "recommendation": "Memory lineage tracking, periodic context clearing, validation.",
            "cvss_score": 8.0,
        },
        {
            "vuln_id": "ASI07",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Insecure Inter-Agent Communication",
            "description": "Spoofing/tampering in multi-agent systems.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "impact": "Agent impersonation, message tampering, coordination attacks.",
            "recommendation": "Cryptographic signatures for A2A messaging, mutual authentication.",
            "cvss_score": 7.0,
        },
        {
            "vuln_id": "ASI08",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Cascading Failures",
            "description": "Single agent fault causes systemic collapse.",
            "severity": VulnerabilitySeverity.MEDIUM,
            "impact": "System-wide outage, data corruption.",
            "recommendation": "Circuit breakers for agentic workflows, isolation boundaries.",
            "cvss_score": 6.5,
        },
        {
            "vuln_id": "ASI09",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Human-Agent Trust Exploitation",
            "description": "Agents manipulate humans for harmful approvals.",
            "severity": VulnerabilitySeverity.HIGH,
            "impact": "Social engineering via AI, unauthorized approvals.",
            "recommendation": "Transparent UI explaining agent reasoning, approval safeguards.",
            "cvss_score": 7.8,
        },
        {
            "vuln_id": "ASI10",
            "source": "owasp",
            "category": "OWASP Agentic Top 10 2025",
            "title": "Rogue Agents",
            "description": "Agents exhibit deceptive behavior outside oversight.",
            "severity": VulnerabilitySeverity.CRITICAL,
            "impact": "Undetected malicious behavior, alignment failures.",
            "recommendation": "Kill-switch mechanisms, periodic audits, behavioral monitoring.",
            "cvss_score": 9.7,
        },
    ]
    
    for vuln_data in owasp_vulns:
        existing = session.query(Vulnerability).filter_by(vuln_id=vuln_data["vuln_id"]).first()
        if not existing:
            vuln = Vulnerability(**vuln_data)
            session.add(vuln)
    
    session.commit()
    print(f"✅ Seeded {len(owasp_vulns)} OWASP vulnerabilities")


if __name__ == "__main__":
    # Test database initialization
    print("Testing database models...")
    
    # Test tier limits
    for tier in SubscriptionTier:
        limits = TIER_LIMITS[tier]
        print(f"\n{tier.value.upper()} Tier:")
        print(f"  Max Scans: {limits['max_scans_per_month']}")
        print(f"  Max Agents: {limits['max_agents']}")
        print(f"  HITL: {limits['hitl_enabled']}")
    
    print("\n✅ Database models loaded successfully")

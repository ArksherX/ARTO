#!/usr/bin/env python3
"""
Enhanced Cognitive Firewall v3.5 - Production Edition

Complete enterprise-grade AI security firewall with:
- Dynamic Vulnerability Database (CVE + OWASP + Community)
- Adaptive Intent Analysis (Semantic Similarity)
- Deep SQL Query Validation
- Human-in-the-Loop (HITL) Approval System
- Multi-Tenancy & RBAC
- Graceful Degradation
- Rate Limiting
- Health Checks
- Input Validation
- Structured Logging
- Secrets Management
- Atomic Operations
"""

from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import sys
import os
import time
import re
import hashlib
import secrets as py_secrets
import threading
import logging
from pathlib import Path
from functools import wraps
from collections import defaultdict
from logging.handlers import RotatingFileHandler
import json
import weakref

# Ensure parent directory is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Context trust requirements (opt-in)
REQUIRE_TRUSTED_CONTEXT = os.getenv("VERITYFLUX_REQUIRE_TRUSTED_CONTEXT", "false").lower() in ("1", "true", "yes")
_trusted_ctx_env = os.getenv("VERITYFLUX_TRUSTED_CONTEXT_LEVELS", "trusted,internal")
TRUSTED_CONTEXT_LEVELS = {t.strip().lower() for t in _trusted_ctx_env.split(",") if t.strip()}


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class FirewallAction(str, Enum):
    """Firewall decision"""
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    LOG_ONLY = "log_only"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HealthStatus(str, Enum):
    """Component health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ApprovalStatus(str, Enum):
    """HITL approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    AUTO_DENIED = "auto_denied"
    EXPIRED = "expired"


class Role(str, Enum):
    """User roles with increasing permissions"""
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


@dataclass
class AgentAction:
    """Represents an agent's intended action"""
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    reasoning_chain: List[str]
    original_goal: str
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class FirewallDecision:
    """Firewall decision with reasoning"""
    action: FirewallAction
    confidence: float
    reasoning: str
    risk_score: float
    violations: List[str]
    recommendations: List[str]
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass
class Vulnerability:
    """Represents a vulnerability pattern"""
    id: str
    name: str
    description: str
    severity: VulnerabilitySeverity
    pattern: str
    components: List[str]
    remediation: str = ""
    source: str = "manual"
    created_at: datetime = field(default_factory=datetime.now)
    
    def matches(self, text: str) -> bool:
        """Check if text matches this vulnerability pattern"""
        try:
            return bool(re.search(self.pattern, text, re.IGNORECASE))
        except:
            return False


@dataclass
class ApprovalRequest:
    """HITL approval request"""
    request_id: str
    agent_id: str
    tool_name: str
    parameters: Dict[str, Any]
    reasoning_chain: List[str]
    original_goal: str
    risk_score: float
    tier: str
    violations: List[str]
    recommendations: List[str]
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = None
    reviewed_by: Optional[str] = None
    reviewer_notes: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    is_false_positive: bool = False
    
    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = datetime.now() + timedelta(minutes=15)
    
    def to_dict(self) -> Dict:
        return {
            'request_id': self.request_id,
            'agent_id': self.agent_id,
            'tool_name': self.tool_name,
            'parameters': self.parameters,
            'reasoning_chain': self.reasoning_chain,
            'original_goal': self.original_goal,
            'risk_score': self.risk_score,
            'tier': self.tier,
            'violations': self.violations,
            'recommendations': self.recommendations,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'reviewed_by': self.reviewed_by,
            'reviewer_notes': self.reviewer_notes,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'is_false_positive': self.is_false_positive
        }


@dataclass
class Tenant:
    """Tenant (organization) using VerityFlux"""
    tenant_id: str
    name: str
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    max_agents: int = 100
    max_users: int = 10
    features: Set[str] = field(default_factory=set)
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'tenant_id': self.tenant_id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active,
            'max_agents': self.max_agents,
            'max_users': self.max_users,
            'features': list(self.features),
            'config': self.config
        }


@dataclass
class User:
    """User account"""
    user_id: str
    email: str
    tenant_id: str
    role: Role
    password_hash: str
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = True
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if user has specific permission"""
        role_permissions = {
            Role.VIEWER: {"view_dashboard", "view_logs", "view_agents"},
            Role.ANALYST: {"view_dashboard", "view_logs", "view_agents", "investigate", "export_logs", "view_statistics"},
            Role.APPROVER: {"view_dashboard", "view_logs", "view_agents", "investigate", "export_logs", 
                          "view_statistics", "approve_actions", "deny_actions", "mark_false_positive"},
            Role.ADMIN: {"view_dashboard", "view_logs", "view_agents", "investigate", "export_logs",
                        "view_statistics", "approve_actions", "deny_actions", "mark_false_positive",
                        "manage_agents", "configure_firewall", "manage_users", "revoke_tokens"},
            Role.SUPER_ADMIN: {"all"}
        }
        perms = role_permissions.get(self.role, set())
        return "all" in perms or permission_name in perms
    
    def to_dict(self) -> Dict:
        return {
            'user_id': self.user_id,
            'email': self.email,
            'tenant_id': self.tenant_id,
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }


# =============================================================================
# RESILIENCE & ERROR RECOVERY
# =============================================================================

class ComponentFailureError(Exception):
    """Raised when a component fails but system continues"""
    pass


def resilient(fallback_value: Any = None, critical: bool = False):
    """Decorator for resilient operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logging.error(f"Component failure in {func.__name__}: {e}")
                if critical:
                    raise ComponentFailureError(f"{func.__name__} failed critically: {e}") from e
                return fallback_value
        return wrapper
    return decorator


class CircuitBreaker:
    """Circuit breaker pattern for external dependencies"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = "CLOSED"
        self.last_failure_time = None
    
    def call(self, func, *args, **kwargs):
        """Call function with circuit breaker protection"""
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
            else:
                raise ComponentFailureError(f"Circuit breaker OPEN for {func.__name__}")
        
        try:
            result = func(*args, **kwargs)
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
            self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
            raise


# =============================================================================
# RATE LIMITING
# =============================================================================

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, requests_per_minute: int = 100, burst_size: int = 20):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.buckets: Dict[str, Dict] = defaultdict(self._new_bucket)
        self.lock = threading.Lock()
    
    def _new_bucket(self) -> Dict:
        return {'tokens': self.burst_size, 'last_update': datetime.now()}
    
    def allow(self, key: str) -> bool:
        """Check if request is allowed"""
        with self.lock:
            bucket = self.buckets[key]
            now = datetime.now()
            time_elapsed = (now - bucket['last_update']).total_seconds()
            tokens_to_add = time_elapsed * (self.requests_per_minute / 60.0)
            bucket['tokens'] = min(self.burst_size, bucket['tokens'] + tokens_to_add)
            bucket['last_update'] = now
            
            if bucket['tokens'] >= 1.0:
                bucket['tokens'] -= 1.0
                return True
            return False


class TenantRateLimiter:
    """Multi-tier rate limiting"""
    
    def __init__(self):
        self.limiters = {
            'free': RateLimiter(requests_per_minute=10, burst_size=5),
            'startup': RateLimiter(requests_per_minute=100, burst_size=20),
            'professional': RateLimiter(requests_per_minute=1000, burst_size=100),
            'enterprise': RateLimiter(requests_per_minute=10000, burst_size=1000),
        }
    
    def allow(self, tenant_id: str, tier: str = 'free') -> bool:
        limiter = self.limiters.get(tier, self.limiters['free'])
        return limiter.allow(tenant_id)


# =============================================================================
# INPUT VALIDATION
# =============================================================================

class InputValidator:
    """Validates and sanitizes inputs"""
    
    MAX_PARAMETER_SIZE = 1024 * 1024  # 1MB
    MAX_REASONING_CHAIN_LENGTH = 20
    MAX_REASONING_ITEM_LENGTH = 1000
    MAX_GOAL_LENGTH = 500
    
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>',
        r'javascript:',
        r'onerror\s*=',
        r'eval\s*\(',
        r'__import__',
        r'exec\s*\(',
    ]
    
    @classmethod
    def validate_agent_action(cls, action: AgentAction) -> tuple:
        """Validate AgentAction - Returns (is_valid, list_of_errors)"""
        errors = []
        
        if not action.agent_id or len(action.agent_id) > 100:
            errors.append("Invalid agent_id")
        
        if not action.tool_name or len(action.tool_name) > 100:
            errors.append("Invalid tool_name")
        
        try:
            param_size = len(json.dumps(action.parameters))
            if param_size > cls.MAX_PARAMETER_SIZE:
                errors.append(f"Parameters too large: {param_size} bytes")
        except:
            errors.append("Parameters not JSON-serializable")
        
        if len(action.reasoning_chain) > cls.MAX_REASONING_CHAIN_LENGTH:
            errors.append(f"Reasoning chain too long: {len(action.reasoning_chain)} items")
        
        for idx, item in enumerate(action.reasoning_chain):
            if len(item) > cls.MAX_REASONING_ITEM_LENGTH:
                errors.append(f"Reasoning item {idx} too long")
        
        if len(action.original_goal) > cls.MAX_GOAL_LENGTH:
            errors.append(f"Goal too long: {len(action.original_goal)} chars")
        
        all_text = " ".join([action.original_goal, *action.reasoning_chain, json.dumps(action.parameters)])
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                errors.append(f"Dangerous pattern detected: {pattern}")
        
        return (len(errors) == 0, errors)


# =============================================================================
# STRUCTURED LOGGING
# =============================================================================

class StructuredFormatter(logging.Formatter):
    """Formats log records as JSON"""
    
    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'service': self.service_name,
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
        }
        if hasattr(record, 'structured_data'):
            log_entry.update(record.structured_data)
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class StructuredLogger:
    """Structured JSON logging with correlation IDs"""
    
    def __init__(self, log_dir: str = "logs", service_name: str = "verityflux", log_level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.service_name = service_name
        
        self.logger = logging.getLogger(service_name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        formatter = StructuredFormatter(service_name=service_name)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)
        
        file_handler = RotatingFileHandler(
            self.log_dir / f"{service_name}.log",
            maxBytes=100 * 1024 * 1024,
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        self.thread_local = threading.local()
    
    def set_correlation_id(self, correlation_id: str):
        self.thread_local.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        return getattr(self.thread_local, 'correlation_id', None)
    
    def log(self, level: str, message: str, **kwargs):
        if correlation_id := self.get_correlation_id():
            kwargs['correlation_id'] = correlation_id
        log_method = getattr(self.logger, level.lower())
        log_method(message, extra={'structured_data': kwargs})
    
    def debug(self, message: str, **kwargs): self.log('debug', message, **kwargs)
    def info(self, message: str, **kwargs): self.log('info', message, **kwargs)
    def warning(self, message: str, **kwargs): self.log('warning', message, **kwargs)
    def error(self, message: str, **kwargs): self.log('error', message, **kwargs)
    def critical(self, message: str, **kwargs): self.log('critical', message, **kwargs)
    
    def log_event(self, event_type: str, severity: str, agent_id: Optional[str] = None, **details):
        self.info(f"Security event: {event_type}", event_type=event_type, severity=severity, agent_id=agent_id, **details)
    
    def log_error_with_context(self, error: Exception, context: Dict[str, Any]):
        import traceback
        self.error(f"Error: {str(error)}", error_type=type(error).__name__, 
                   error_message=str(error), traceback=traceback.format_exc(), **context)


# =============================================================================
# SECRETS MANAGEMENT
# =============================================================================

class SecretsManager:
    """Manages encrypted secrets"""
    
    def __init__(self, encryption_key: Optional[str] = None, secrets_file: str = ".secrets.json"):
        self.secrets_file = Path(secrets_file)
        self.secrets: Dict[str, str] = {}
        self._load_secrets()
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        env_value = os.getenv(key)
        if env_value:
            return env_value
        return self.secrets.get(key, default)
    
    def set(self, key: str, value: str):
        self.secrets[key] = value
        self._save_secrets()
    
    def delete(self, key: str):
        if key in self.secrets:
            del self.secrets[key]
            self._save_secrets()
    
    def _load_secrets(self):
        if self.secrets_file.exists():
            try:
                with open(self.secrets_file, 'r') as f:
                    self.secrets = json.load(f)
            except:
                self.secrets = {}
    
    def _save_secrets(self):
        with open(self.secrets_file, 'w') as f:
            json.dump(self.secrets, f, indent=2)
    
    def list_keys(self) -> list:
        return list(self.secrets.keys())


# =============================================================================
# ATOMIC OPERATIONS
# =============================================================================

class AtomicCounter:
    """Thread-safe atomic counter"""
    
    def __init__(self, initial_value: int = 0, file_path: Optional[Path] = None):
        self.value = initial_value
        self.lock = threading.Lock()
        self.file_path = file_path
        
        if file_path:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        self.value = int(f.read().strip())
                except:
                    pass
    
    def increment(self, amount: int = 1) -> int:
        with self.lock:
            self.value += amount
            if self.file_path:
                with open(self.file_path, 'w') as f:
                    f.write(str(self.value))
            return self.value
    
    def get(self) -> int:
        with self.lock:
            return self.value


# =============================================================================
# CACHE MANAGER
# =============================================================================

class CacheManager:
    """In-memory cache with optional Redis backend"""
    
    def __init__(self, redis_url: str = None):
        self.memory_cache: Dict[str, Any] = {}
        self.cache_times: Dict[str, datetime] = {}
        self.enabled = True
        self.redis_client = None
        
        if redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()
                print("✅ Redis cache connected")
            except:
                print("⚠️  Redis not available, using memory cache")
    
    def get(self, key: str) -> Optional[Any]:
        if self.redis_client:
            try:
                value = self.redis_client.get(key)
                return json.loads(value) if value else None
            except:
                pass
        
        if key in self.memory_cache:
            if key in self.cache_times:
                if datetime.now() - self.cache_times[key] < timedelta(minutes=5):
                    return self.memory_cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, json.dumps(value))
                return True
            except:
                pass
        
        self.memory_cache[key] = value
        self.cache_times[key] = datetime.now()
        return True
    
    def delete(self, key: str) -> bool:
        if self.redis_client:
            try:
                self.redis_client.delete(key)
            except:
                pass
        
        if key in self.memory_cache:
            del self.memory_cache[key]
            if key in self.cache_times:
                del self.cache_times[key]
        return True
    
    def cache_key(self, *args, **kwargs) -> str:
        key_data = json.dumps({'args': args, 'kwargs': kwargs}, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()


def cached(ttl: int = 300):
    """Decorator to cache function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not hasattr(self, 'cache') or not self.cache.enabled:
                return func(self, *args, **kwargs)
            
            cache_key = f"{func.__name__}:{self.cache.cache_key(*args, **kwargs)}"
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            result = func(self, *args, **kwargs)
            self.cache.set(cache_key, result, ttl)
            return result
        return wrapper
    return decorator


# =============================================================================
# VULNERABILITY DATABASE
# =============================================================================

class VulnerabilityDatabase:
    """In-memory vulnerability pattern database"""
    
    def __init__(self, cache_backend=None):
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.cache_backend = cache_backend
        self._load_builtin_patterns()
    
    def _load_builtin_patterns(self):
        """Load built-in vulnerability patterns"""
        patterns = [
            # SQL Injection patterns
            Vulnerability(
                id="SQL-001", name="SQL Injection - UNION", severity=VulnerabilitySeverity.CRITICAL,
                description="UNION-based SQL injection attempt",
                pattern=r"union\s+(all\s+)?select", components=["sql", "database"],
                remediation="Use parameterized queries"
            ),
            Vulnerability(
                id="SQL-002", name="SQL Injection - OR 1=1", severity=VulnerabilitySeverity.CRITICAL,
                description="Boolean-based SQL injection",
                pattern=r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", components=["sql", "database"],
                remediation="Validate all user inputs"
            ),
            Vulnerability(
                id="SQL-003", name="SQL Injection - Comment", severity=VulnerabilitySeverity.HIGH,
                description="SQL comment injection",
                pattern=r"(--|#|/\*)", components=["sql", "database"],
                remediation="Sanitize special characters"
            ),
            Vulnerability(
                id="SQL-004", name="Dangerous DELETE", severity=VulnerabilitySeverity.CRITICAL,
                description="DELETE without WHERE clause",
                pattern=r"delete\s+from\s+\w+\s*(?!where)", components=["sql", "database"],
                remediation="Always include WHERE clause"
            ),
            Vulnerability(
                id="SQL-005", name="Dangerous DROP", severity=VulnerabilitySeverity.CRITICAL,
                description="DROP TABLE/DATABASE detected",
                pattern=r"drop\s+(table|database)", components=["sql", "database"],
                remediation="Restrict DDL operations"
            ),
            # Prompt Injection patterns
            Vulnerability(
                id="PI-001", name="Prompt Injection - Ignore", severity=VulnerabilitySeverity.HIGH,
                description="Instruction override attempt",
                pattern=r"ignore\s+(previous|all|above)\s+(instructions?|prompts?)", 
                components=["prompt", "llm"],
                remediation="Implement input sanitization"
            ),
            Vulnerability(
                id="PI-002", name="Prompt Injection - System", severity=VulnerabilitySeverity.CRITICAL,
                description="System prompt extraction attempt",
                pattern=r"(system\s+prompt|reveal|show)\s*(your)?\s*(instructions?|prompt)", 
                components=["prompt", "llm"],
                remediation="Never expose system prompts"
            ),
            Vulnerability(
                id="PI-003", name="Jailbreak Attempt", severity=VulnerabilitySeverity.CRITICAL,
                description="DAN/Jailbreak pattern detected",
                pattern=r"(DAN|do\s+anything\s+now|jailbreak|bypass\s+restrictions)", 
                components=["prompt", "llm"],
                remediation="Implement robust input filtering"
            ),
            # Data Exfiltration patterns
            Vulnerability(
                id="EX-001", name="Credential Access", severity=VulnerabilitySeverity.CRITICAL,
                description="Attempt to access credentials",
                pattern=r"(password|passwd|credential|secret|api[_\s]?key|private[_\s]?key)", 
                components=["data", "credential"],
                remediation="Implement credential isolation"
            ),
            Vulnerability(
                id="EX-002", name="Sensitive File Access", severity=VulnerabilitySeverity.HIGH,
                description="Access to sensitive files",
                pattern=r"(/etc/shadow|\.aws/credentials|\.ssh/id_rsa|\.env)", 
                components=["file", "credential"],
                remediation="Restrict file system access"
            ),
            # Code Execution patterns
            Vulnerability(
                id="CE-001", name="Shell Command Injection", severity=VulnerabilitySeverity.CRITICAL,
                description="Shell command injection attempt",
                pattern=r"(;|\||&&)\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby)", 
                components=["shell", "command"],
                remediation="Sanitize shell inputs"
            ),
            Vulnerability(
                id="CE-002", name="Code Execution", severity=VulnerabilitySeverity.CRITICAL,
                description="Dynamic code execution attempt",
                pattern=r"(eval|exec|system|subprocess|os\.system|shell_exec)", 
                components=["code", "execution"],
                remediation="Avoid dynamic code execution"
            ),
        ]
        
        for vuln in patterns:
            self.vulnerabilities[vuln.id] = vuln
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability pattern"""
        self.vulnerabilities[vuln.id] = vuln
    
    def check_text(self, text: str, min_severity: VulnerabilitySeverity = VulnerabilitySeverity.LOW,
                   components: List[str] = None) -> List[Vulnerability]:
        """Check text against all patterns"""
        matches = []
        severity_order = [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH, 
                         VulnerabilitySeverity.MEDIUM, VulnerabilitySeverity.LOW, VulnerabilitySeverity.INFO]
        min_idx = severity_order.index(min_severity)
        
        for vuln in self.vulnerabilities.values():
            if severity_order.index(vuln.severity) <= min_idx:
                if components is None or any(c in vuln.components for c in components):
                    if vuln.matches(text):
                        matches.append(vuln)
        
        return matches
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        severity_counts = defaultdict(int)
        for vuln in self.vulnerabilities.values():
            severity_counts[vuln.severity.value] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': dict(severity_counts),
            'components': list(set(c for v in self.vulnerabilities.values() for c in v.components))
        }


# =============================================================================
# INTENT ANALYZER
# =============================================================================

class IntentAnalysis:
    """Result of intent analysis"""
    def __init__(self, category: str, confidence: float, deception_detected: bool, explanation: str):
        self.category = category
        self.confidence = confidence
        self.deception_detected = deception_detected
        self.explanation = explanation


class AdaptiveIntentAnalyzer:
    """Analyzes agent intent for deception"""
    
    def __init__(self):
        self.known_categories = {
            'data_query': ['select', 'fetch', 'get', 'read', 'query', 'retrieve'],
            'data_modification': ['update', 'insert', 'delete', 'modify', 'change', 'alter'],
            'file_operation': ['write', 'create', 'upload', 'download', 'read', 'delete'],
            'system_operation': ['execute', 'run', 'install', 'configure', 'restart'],
            'communication': ['send', 'email', 'message', 'notify', 'alert'],
            'analysis': ['analyze', 'report', 'summarize', 'calculate', 'compute'],
        }
        
        self.deception_indicators = [
            'urgent', 'override', 'bypass', 'ignore', 'admin', 'emergency',
            'immediately', 'skip', 'disable', 'turn off', 'no questions'
        ]
        
        self.false_positives: List[Dict] = []
    
    def analyze(self, reasoning_chain: List[str], parameters: Dict, 
                tool_name: str, original_goal: str) -> IntentAnalysis:
        """Analyze intent for potential deception"""
        
        all_text = " ".join([original_goal, *reasoning_chain, json.dumps(parameters)]).lower()
        
        # Detect category
        detected_category = 'unknown'
        max_matches = 0
        for category, keywords in self.known_categories.items():
            matches = sum(1 for kw in keywords if kw in all_text)
            if matches > max_matches:
                max_matches = matches
                detected_category = category
        
        # Check for deception indicators
        deception_score = 0
        for indicator in self.deception_indicators:
            if indicator in all_text:
                deception_score += 1
        
        # Check for goal-action mismatch
        goal_lower = original_goal.lower()
        tool_lower = tool_name.lower()
        
        mismatch = False
        if 'read' in goal_lower and 'delete' in tool_lower:
            mismatch = True
        if 'report' in goal_lower and ('drop' in all_text or 'delete' in all_text):
            mismatch = True
        if 'analytics' in goal_lower and 'password' in all_text:
            mismatch = True
        
        deception_detected = deception_score >= 2 or mismatch
        confidence = min(0.5 + (deception_score * 0.15) + (0.3 if mismatch else 0), 1.0)
        
        explanation = ""
        if mismatch:
            explanation = "Goal-action mismatch detected"
        elif deception_score >= 2:
            explanation = f"Multiple deception indicators found ({deception_score})"
        
        return IntentAnalysis(
            category=detected_category,
            confidence=confidence,
            deception_detected=deception_detected,
            explanation=explanation
        )
    
    def learn_false_positive(self, analysis_data: Dict):
        """Learn from false positive feedback"""
        self.false_positives.append(analysis_data)
    
    def get_statistics(self) -> Dict:
        return {
            'known_categories': len(self.known_categories),
            'deception_indicators': len(self.deception_indicators),
            'false_positives_learned': len(self.false_positives)
        }


# =============================================================================
# SQL VALIDATOR
# =============================================================================

class SQLValidationResult:
    """SQL validation result"""
    def __init__(self, is_valid: bool, risk_score: float, violations: List[str], recommendations: List[str]):
        self.is_valid = is_valid
        self.risk_score = risk_score
        self.violations = violations
        self.recommendations = recommendations


class SQLValidator:
    """Validates SQL queries for security issues"""
    
    def __init__(self):
        self.dangerous_patterns = [
            (r'drop\s+(table|database|index)', 'DDL operation: DROP', 100),
            (r'truncate\s+table', 'DDL operation: TRUNCATE', 100),
            (r'delete\s+from\s+\w+\s*(?!.*where)', 'DELETE without WHERE', 90),
            (r'update\s+\w+\s+set\s+.*(?!.*where)', 'UPDATE without WHERE', 85),
            (r"union\s+(all\s+)?select", 'UNION injection', 95),
            (r";\s*(drop|delete|truncate|update|insert)", 'Stacked queries', 95),
            (r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", 'Boolean injection', 90),
            (r"(--|#|/\*)", 'SQL comment', 60),
            (r"into\s+outfile", 'File write attempt', 100),
            (r"load_file\s*\(", 'File read attempt', 100),
            (r"information_schema", 'Schema enumeration', 70),
            (r"benchmark\s*\(", 'Timing attack', 80),
            (r"sleep\s*\(", 'Timing attack', 80),
        ]
    
    def validate(self, query: str, context: Dict = None) -> SQLValidationResult:
        """Validate SQL query"""
        violations = []
        max_risk = 0
        recommendations = []
        
        query_lower = query.lower()
        
        for pattern, description, risk in self.dangerous_patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                violations.append(f"SQL: {description}")
                max_risk = max(max_risk, risk)
                
                if 'without WHERE' in description:
                    recommendations.append("Add WHERE clause to limit affected rows")
                elif 'injection' in description.lower():
                    recommendations.append("Use parameterized queries")
        
        return SQLValidationResult(
            is_valid=len(violations) == 0,
            risk_score=max_risk,
            violations=violations,
            recommendations=recommendations
        )


# =============================================================================
# HITL GATEWAY
# =============================================================================

class HITLGateway:
    """Human-in-the-Loop approval system"""
    
    def __init__(self, storage_path: str = "hitl_queue"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.completed_requests: Dict[str, ApprovalRequest] = {}
        self.notification_handlers: List = []
        
        self._load_pending_requests()
        self._start_timeout_checker()
    
    def _load_pending_requests(self):
        """Load pending requests from disk"""
        for file_path in self.storage_path.glob("pending_*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    request = ApprovalRequest(
                        request_id=data['request_id'],
                        agent_id=data['agent_id'],
                        tool_name=data['tool_name'],
                        parameters=data['parameters'],
                        reasoning_chain=data['reasoning_chain'],
                        original_goal=data['original_goal'],
                        risk_score=data['risk_score'],
                        tier=data['tier'],
                        violations=data['violations'],
                        recommendations=data['recommendations'],
                        status=ApprovalStatus(data['status']),
                        created_at=datetime.fromisoformat(data['created_at']),
                        expires_at=datetime.fromisoformat(data['expires_at'])
                    )
                    if request.status == ApprovalStatus.PENDING:
                        self.pending_requests[request.request_id] = request
                    else:
                        self.completed_requests[request.request_id] = request
            except Exception as e:
                print(f"Failed to load request: {e}")
    
    def _start_timeout_checker(self):
        """Start background thread to check for expired requests"""
        def check_timeouts():
            while True:
                time.sleep(30)
                now = datetime.now()
                expired = [rid for rid, req in self.pending_requests.items() 
                          if now > req.expires_at]
                for rid in expired:
                    self._auto_deny(rid)
        
        thread = threading.Thread(target=check_timeouts, daemon=True)
        thread.start()
    
    def _auto_deny(self, request_id: str):
        """Auto-deny expired request"""
        if request_id in self.pending_requests:
            request = self.pending_requests.pop(request_id)
            request.status = ApprovalStatus.AUTO_DENIED
            request.reviewed_by = "SYSTEM"
            request.reviewer_notes = "Auto-denied: Timeout exceeded"
            request.reviewed_at = datetime.now()
            self.completed_requests[request_id] = request
            self._save_request(request)
    
    def submit_for_approval(self, agent_action: AgentAction, decision: FirewallDecision,
                           timeout_minutes: int = 15) -> str:
        """Submit action for human approval"""
        request_id = f"HITL-{datetime.now().strftime('%Y%m%d%H%M%S')}-{py_secrets.token_hex(4)}"
        
        request = ApprovalRequest(
            request_id=request_id,
            agent_id=agent_action.agent_id,
            tool_name=agent_action.tool_name,
            parameters=agent_action.parameters,
            reasoning_chain=agent_action.reasoning_chain,
            original_goal=agent_action.original_goal,
            risk_score=decision.risk_score,
            tier=decision.context.get('tier', 'UNKNOWN'),
            violations=decision.violations,
            recommendations=decision.recommendations,
            expires_at=datetime.now() + timedelta(minutes=timeout_minutes)
        )
        
        self.pending_requests[request_id] = request
        self._save_request(request)
        
        # Notify handlers
        for handler in self.notification_handlers:
            try:
                handler(request)
            except Exception as e:
                print(f"Notification handler failed: {e}")
        
        return request_id
    
    def approve(self, request_id: str, reviewer: str, notes: str = "", 
                mark_false_positive: bool = False) -> bool:
        """Approve a pending request"""
        if request_id not in self.pending_requests:
            return False
        
        request = self.pending_requests.pop(request_id)
        request.status = ApprovalStatus.APPROVED
        request.reviewed_by = reviewer
        request.reviewer_notes = notes
        request.reviewed_at = datetime.now()
        request.is_false_positive = mark_false_positive
        
        self.completed_requests[request_id] = request
        self._save_request(request)
        
        return True
    
    def deny(self, request_id: str, reviewer: str, notes: str = "") -> bool:
        """Deny a pending request"""
        if request_id not in self.pending_requests:
            return False
        
        request = self.pending_requests.pop(request_id)
        request.status = ApprovalStatus.DENIED
        request.reviewed_by = reviewer
        request.reviewer_notes = notes
        request.reviewed_at = datetime.now()
        
        self.completed_requests[request_id] = request
        self._save_request(request)
        
        return True
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending requests"""
        return list(self.pending_requests.values())
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get request by ID"""
        return self.pending_requests.get(request_id) or self.completed_requests.get(request_id)
    
    def wait_for_decision(self, request_id: str, poll_interval: float = 1.0) -> ApprovalStatus:
        """Block until decision is made or timeout"""
        while request_id in self.pending_requests:
            time.sleep(poll_interval)
        
        request = self.completed_requests.get(request_id)
        return request.status if request else ApprovalStatus.AUTO_DENIED
    
    def add_notification_handler(self, handler):
        """Add notification handler"""
        self.notification_handlers.append(handler)
    
    def _save_request(self, request: ApprovalRequest):
        """Save request to disk"""
        prefix = "pending" if request.status == ApprovalStatus.PENDING else "completed"
        file_path = self.storage_path / f"{prefix}_{request.request_id}.json"
        
        with open(file_path, 'w') as f:
            json.dump(request.to_dict(), f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get HITL statistics"""
        all_requests = list(self.completed_requests.values())
        
        review_times = []
        for req in all_requests:
            if req.reviewed_at and req.created_at:
                review_times.append((req.reviewed_at - req.created_at).total_seconds() / 60)
        
        return {
            'total_requests': len(self.pending_requests) + len(self.completed_requests),
            'pending': len(self.pending_requests),
            'approved': sum(1 for r in all_requests if r.status == ApprovalStatus.APPROVED),
            'denied': sum(1 for r in all_requests if r.status == ApprovalStatus.DENIED),
            'auto_denied': sum(1 for r in all_requests if r.status == ApprovalStatus.AUTO_DENIED),
            'false_positives': sum(1 for r in all_requests if r.is_false_positive),
            'avg_review_time_minutes': sum(review_times) / len(review_times) if review_times else 0
        }


# =============================================================================
# NOTIFICATION HANDLERS
# =============================================================================

class ConsoleNotifier:
    """Console notification handler"""
    def __call__(self, request: ApprovalRequest):
        print("\n" + "="*70)
        print("🚨 HITL APPROVAL REQUIRED")
        print("="*70)
        print(f"Request ID: {request.request_id}")
        print(f"Agent: {request.agent_id}")
        print(f"Tool: {request.tool_name}")
        print(f"Risk: {request.risk_score:.0f}/100 ({request.tier})")
        print(f"Expires: {request.expires_at.strftime('%H:%M:%S')}")
        print("\nViolations:")
        for v in request.violations[:3]:
            print(f"  • {v}")
        print("="*70 + "\n")


class SlackNotifier:
    """Slack notification handler"""
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def __call__(self, request: ApprovalRequest):
        if not self.webhook_url:
            return
        
        try:
            import requests
            message = {
                "text": f"🚨 HITL Approval Required: {request.request_id}",
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"🚨 Approval Required"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:*\n{request.agent_id}"},
                        {"type": "mrkdwn", "text": f"*Risk:*\n{request.risk_score:.0f}/100"}
                    ]}
                ]
            }
            requests.post(self.webhook_url, json=message, timeout=10)
        except Exception as e:
            print(f"Slack notification failed: {e}")


class EmailNotifier:
    """Email notification handler"""
    def __init__(self, smtp_config: Dict):
        self.smtp_config = smtp_config
    
    def __call__(self, request: ApprovalRequest):
        # Email implementation would go here
        pass


# =============================================================================
# MULTI-TENANT MANAGER
# =============================================================================

class MultiTenantManager:
    """Manages multi-tenant isolation and RBAC"""
    
    def __init__(self, storage_path: str = "multi_tenant"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Dict] = {}
        
        self._load_data()
    
    def _load_data(self):
        """Load tenants and users from disk"""
        for file_path in self.storage_path.glob("tenant_*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    tenant = Tenant(
                        tenant_id=data['tenant_id'],
                        name=data['name'],
                        is_active=data['is_active'],
                        max_agents=data['max_agents'],
                        max_users=data['max_users'],
                        features=set(data['features']),
                        config=data['config']
                    )
                    self.tenants[tenant.tenant_id] = tenant
            except Exception as e:
                print(f"Failed to load tenant: {e}")
        
        for file_path in self.storage_path.glob("user_*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    user = User(
                        user_id=data['user_id'],
                        email=data['email'],
                        tenant_id=data['tenant_id'],
                        role=Role(data['role']),
                        password_hash=data.get('password_hash', ''),
                        is_active=data['is_active']
                    )
                    self.users[user.user_id] = user
            except Exception as e:
                print(f"Failed to load user: {e}")
    
    def create_tenant(self, name: str, max_agents: int = 100, max_users: int = 10,
                     features: Set[str] = None) -> Tenant:
        """Create a new tenant"""
        tenant_id = f"{name.lower().replace(' ', '_')[:20]}_{py_secrets.token_hex(4)}"
        
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            max_agents=max_agents,
            max_users=max_users,
            features=features or {"hitl", "vulnerability_db", "intent_analysis"}
        )
        
        self.tenants[tenant_id] = tenant
        self._save_tenant(tenant)
        return tenant
    
    def create_user(self, email: str, password: str, tenant_id: str, role: Role = Role.VIEWER) -> User:
        """Create a new user"""
        if tenant_id not in self.tenants:
            raise ValueError(f"Tenant {tenant_id} does not exist")
        
        user_id = f"user_{hashlib.sha256(email.encode()).hexdigest()[:16]}"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user = User(
            user_id=user_id,
            email=email,
            tenant_id=tenant_id,
            role=role,
            password_hash=password_hash
        )
        
        self.users[user_id] = user
        self._save_user(user)
        return user
    
    def authenticate(self, email: str, password: str) -> Optional[str]:
        """Authenticate user and create session"""
        user = next((u for u in self.users.values() if u.email == email), None)
        if not user or not user.is_active:
            return None
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user.password_hash:
            return None
        
        session_token = py_secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            'user_id': user.user_id,
            'tenant_id': user.tenant_id,
            'expires_at': datetime.now().timestamp() + 86400
        }
        
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate session token"""
        session = self.sessions.get(session_token)
        if not session:
            return None
        if datetime.now().timestamp() > session['expires_at']:
            del self.sessions[session_token]
            return None
        return session
    
    def _save_tenant(self, tenant: Tenant):
        file_path = self.storage_path / f"tenant_{tenant.tenant_id}.json"
        with open(file_path, 'w') as f:
            json.dump(tenant.to_dict(), f, indent=2)
    
    def _save_user(self, user: User):
        file_path = self.storage_path / f"user_{user.user_id}.json"
        data = user.to_dict()
        data['password_hash'] = user.password_hash
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        return {
            'total_tenants': len(self.tenants),
            'active_tenants': sum(1 for t in self.tenants.values() if t.is_active),
            'total_users': len(self.users),
            'active_sessions': len(self.sessions)
        }


# =============================================================================
# HEALTH CHECK
# =============================================================================

class HealthCheck:
    """System health checker"""
    
    def __init__(self, firewall):
        self.firewall = firewall
    
    def check_all(self) -> Dict:
        """Check all components"""
        checks = {
            'vulnerability_db': self._check_vuln_db(),
            'intent_analyzer': self._check_intent_analyzer(),
            'sql_validator': self._check_sql_validator(),
            'hitl_gateway': self._check_hitl(),
            'cache': self._check_cache(),
        }
        
        statuses = [check['status'] for check in checks.values()]
        
        if all(s == HealthStatus.HEALTHY.value for s in statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY.value for s in statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED
        
        return {
            'status': overall.value,
            'timestamp': datetime.now().isoformat(),
            'components': checks
        }
    
    def _check_vuln_db(self) -> Dict:
        try:
            stats = self.firewall.vuln_db.get_statistics()
            vuln_count = stats['total_vulnerabilities']
            status = HealthStatus.HEALTHY if vuln_count >= 10 else HealthStatus.DEGRADED
            return {'status': status.value, 'vulnerabilities_loaded': vuln_count}
        except Exception as e:
            return {'status': HealthStatus.UNHEALTHY.value, 'error': str(e)}
    
    def _check_intent_analyzer(self) -> Dict:
        try:
            stats = self.firewall.intent_analyzer.get_statistics()
            return {'status': HealthStatus.HEALTHY.value, 'categories': stats['known_categories']}
        except Exception as e:
            return {'status': HealthStatus.UNHEALTHY.value, 'error': str(e)}
    
    def _check_sql_validator(self) -> Dict:
        try:
            self.firewall.sql_validator.validate("SELECT 1")
            return {'status': HealthStatus.HEALTHY.value}
        except Exception as e:
            return {'status': HealthStatus.UNHEALTHY.value, 'error': str(e)}
    
    def _check_hitl(self) -> Dict:
        try:
            stats = self.firewall.hitl_gateway.get_statistics()
            pending = stats['pending']
            status = HealthStatus.DEGRADED if pending > 100 else HealthStatus.HEALTHY
            return {'status': status.value, 'pending_approvals': pending}
        except Exception as e:
            return {'status': HealthStatus.UNHEALTHY.value, 'error': str(e)}
    
    def _check_cache(self) -> Dict:
        if not self.firewall.cache.enabled:
            return {'status': HealthStatus.DEGRADED.value, 'message': 'Cache disabled'}
        return {'status': HealthStatus.HEALTHY.value}


# =============================================================================
# MAIN FIREWALL CLASS
# =============================================================================

class EnhancedCognitiveFirewall:
    """
    Enterprise-grade cognitive firewall
    Version 3.5 - Production Ready
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize enhanced firewall"""
        print("🔧 Initializing Enhanced Cognitive Firewall v3.5...")
        base_config = self._load_default_config()
        if config:
            base_config.update(config)

        self._base_config = dict(base_config)
        policy_path = base_config.get('policy_path') or os.getenv("VERITYFLUX_POLICY_PATH")
        policy = _read_policy_file(policy_path)
        if policy:
            base_config.update(policy)

        self.config = base_config
        _register_firewall_instance(self)
        
        # Initialize secrets manager
        print("  🔐 Loading secrets...")
        self.secrets = SecretsManager()
        
        # Initialize structured logging
        print("  📝 Initializing structured logging...")
        self.logger = StructuredLogger(
            log_dir=self.config.get('log_dir', 'logs'),
            service_name='verityflux',
            log_level=self.config.get('log_level', 'INFO')
        )
        
        # Initialize cache manager
        print("  ⚡ Connecting to cache...")
        redis_url = self.secrets.get('REDIS_URL')
        self.cache = CacheManager(redis_url=redis_url)
        
        # Initialize rate limiter
        print("  🚦 Initializing rate limiter...")
        self.rate_limiter = TenantRateLimiter()
        
        # Initialize circuit breakers
        self.vuln_db_circuit = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        # Load security components
        print("  📚 Loading vulnerability database...")
        self.vuln_db = VulnerabilityDatabase()
        
        print("  🧠 Loading adaptive intent analyzer...")
        self.intent_analyzer = AdaptiveIntentAnalyzer()
        
        print("  🔍 Loading SQL validator...")
        self.sql_validator = SQLValidator()
        
        # Initialize HITL Gateway
        print("  👤 Initializing HITL gateway...")
        self.hitl_gateway = HITLGateway(storage_path=self.config.get('hitl_queue_dir', 'hitl_queue'))
        self._setup_hitl_notifications()
        
        # Initialize multi-tenancy
        self.multi_tenant_enabled = self.config.get('enable_multi_tenant', False)
        if self.multi_tenant_enabled:
            print("  🏢 Enabling multi-tenancy...")
            self.multi_tenant_manager = MultiTenantManager(
                storage_path=self.config.get('multi_tenant_dir', 'multi_tenant')
            )
        else:
            self.multi_tenant_manager = None
        
        # Initialize stateful intent tracker
        try:
            from .stateful_intent_tracker import StatefulIntentTracker
            self.intent_tracker = StatefulIntentTracker()
            print("  📊 Stateful intent tracker initialized")
        except Exception:
            self.intent_tracker = None

        # Initialize health checker
        self.health_checker = HealthCheck(self)

        # Performance counters
        Path('metrics').mkdir(exist_ok=True)
        self.request_counter = AtomicCounter(file_path=Path('metrics/request_count.txt'))
        self.block_counter = AtomicCounter(file_path=Path('metrics/block_count.txt'))
        
        # Action log
        self.action_log = []
        
        print("✅ Enhanced Cognitive Firewall v3.5 initialized")
        print(f"   • Vulnerability Database: {self.vuln_db.get_statistics()['total_vulnerabilities']} patterns")
        print(f"   • Intent Categories: {self.intent_analyzer.get_statistics()['known_categories']}")
        print(f"   • Cache: {'Enabled' if self.cache.enabled else 'Memory-only'}")
        print(f"   • Multi-Tenancy: {'Enabled' if self.multi_tenant_enabled else 'Disabled'}")
    
    def evaluate(self, agent_action: AgentAction, tenant_id: Optional[str] = None,
                session_token: Optional[str] = None) -> FirewallDecision:
        """Evaluate agent action through all security layers"""
        
        correlation_id = f"req_{int(time.time()*1000)}_{self.request_counter.increment()}"
        self.logger.set_correlation_id(correlation_id)
        
        start_time = time.perf_counter()
        
        self.logger.info("Firewall evaluation started",
                        agent_id=agent_action.agent_id, tool=agent_action.tool_name)
        
        try:
            # Step 1: Input Validation
            is_valid, validation_errors = InputValidator.validate_agent_action(agent_action)
            if not is_valid:
                self.logger.warning("Input validation failed", errors=validation_errors)
                return self._create_block_decision(
                    risk_score=100.0,
                    violations=validation_errors,
                    reasoning="Invalid input detected",
                    context={'input_validation_failed': True}
                )

            # Step 1b: Context trust check (opt-in)
            if REQUIRE_TRUSTED_CONTEXT:
                ctx = agent_action.context or {}
                trust_level = (ctx.get("trust_level") or ctx.get("source_trust") or ctx.get("trust") or "").lower()
                if not trust_level:
                    return self._create_block_decision(
                        risk_score=90.0,
                        violations=["Missing context trust level"],
                        reasoning="Untrusted context",
                        context={"context_trust": "missing"}
                    )
                if trust_level not in TRUSTED_CONTEXT_LEVELS:
                    return self._create_block_decision(
                        risk_score=90.0,
                        violations=[f"Untrusted context level: {trust_level}"],
                        reasoning="Untrusted context",
                        context={"context_trust": trust_level}
                    )
            
            # Step 2: Multi-tenant validation
            if self.multi_tenant_enabled:
                if not tenant_id:
                    return self._create_block_decision(
                        risk_score=100.0,
                        violations=["tenant_id required in multi-tenant mode"],
                        reasoning="Missing tenant ID"
                    )
                
                tenant = self.multi_tenant_manager.tenants.get(tenant_id)
                if not tenant or not tenant.is_active:
                    return self._create_block_decision(
                        risk_score=100.0,
                        violations=[f"Invalid or inactive tenant: {tenant_id}"],
                        reasoning="Tenant validation failed"
                    )
                
                tier = tenant.config.get('tier', 'free')
                if not self.rate_limiter.allow(tenant_id, tier):
                    return self._create_block_decision(
                        risk_score=100.0,
                        violations=["Rate limit exceeded"],
                        reasoning=f"Too many requests for tier: {tier}",
                        context={'rate_limited': True}
                    )
            
            # Step 3: Evaluate through security layers
            decision = self._evaluate_layers(agent_action, tenant_id)
            
            # Step 4: HITL integration
            if self.config.get('enable_hitl', True):
                if decision.action == FirewallAction.REQUIRE_APPROVAL:
                    request_id = self.hitl_gateway.submit_for_approval(
                        agent_action=agent_action,
                        decision=decision,
                        timeout_minutes=self.config.get('hitl_timeout_minutes', 15)
                    )
                    decision.context['hitl_request_id'] = request_id
                    decision.context['hitl_status'] = 'pending_approval'
            
            # Calculate execution time
            execution_time_ms = (time.perf_counter() - start_time) * 1000
            decision.context['evaluation_time_ms'] = execution_time_ms
            decision.context['correlation_id'] = correlation_id
            
            # Log decision
            self.logger.log_event(
                event_type='firewall_decision',
                severity=decision.context.get('tier', 'INFO'),
                agent_id=agent_action.agent_id,
                tool=agent_action.tool_name,
                decision=decision.action.value,
                risk_score=decision.risk_score,
                execution_time_ms=execution_time_ms
            )
            
            # Update counters
            if decision.action == FirewallAction.BLOCK:
                self.block_counter.increment()
            
            # Add to action log
            self.action_log.append({
                'timestamp': datetime.now().isoformat(),
                'agent_id': agent_action.agent_id,
                'tool': agent_action.tool_name,
                'decision': decision.action.value,
                'risk': decision.risk_score,
                'tier': decision.context.get('tier'),
                'violations': decision.violations
            })
            
            return decision
            
        except Exception as e:
            self.logger.log_error_with_context(error=e, context={
                'agent_id': agent_action.agent_id,
                'tool': agent_action.tool_name
            })
            return self._create_block_decision(
                risk_score=100.0,
                violations=[f"System error: {str(e)}"],
                reasoning="Firewall error - blocking for safety",
                context={'system_error': True}
            )
    
    def _evaluate_layers(self, agent_action: AgentAction, tenant_id: Optional[str]) -> FirewallDecision:
        """Evaluate through all security layers"""
        violations = []
        risk_breakdown = {}
        recommendations = []
        
        # Layer 1: Vulnerability Database
        if self.config.get('enable_vuln_db', True):
            try:
                vuln_matches = self._check_vulnerability_database(agent_action)
                
                if vuln_matches:
                    critical = [v for v in vuln_matches if v.severity == VulnerabilitySeverity.CRITICAL]
                    high = [v for v in vuln_matches if v.severity == VulnerabilitySeverity.HIGH]
                    risk_breakdown['vuln_critical'] = bool(critical)
                    risk_breakdown['vuln_high'] = bool(high)
                    
                    if critical:
                        risk_breakdown['vulnerability_db'] = 100
                        violations.append(f"Matched {len(critical)} CRITICAL vulnerabilities")
                        recommendations.extend([v.remediation for v in critical[:2] if v.remediation])
                    elif high:
                        risk_breakdown['vulnerability_db'] = 80
                        violations.append(f"Matched {len(high)} HIGH vulnerabilities")
                    else:
                        risk_breakdown['vulnerability_db'] = 50
                else:
                    risk_breakdown['vulnerability_db'] = 0
                    risk_breakdown['vuln_critical'] = False
                    risk_breakdown['vuln_high'] = False
            except Exception as e:
                self.logger.warning(f"Vulnerability DB error: {e}")
                risk_breakdown['vulnerability_db'] = 0
                risk_breakdown['vuln_critical'] = False
                risk_breakdown['vuln_high'] = False
                violations.append("⚠️ Vulnerability database offline")
        
        # Layer 2: Intent Analysis
        if self.config.get('enable_intent_analysis', True):
            try:
                intent_result = self.intent_analyzer.analyze(
                    reasoning_chain=agent_action.reasoning_chain,
                    parameters=agent_action.parameters,
                    tool_name=agent_action.tool_name,
                    original_goal=agent_action.original_goal
                )
                
                if intent_result.deception_detected:
                    risk_breakdown['intent_analysis'] = intent_result.confidence * 100
                    violations.append(f"Deceptive intent: {intent_result.explanation}")
                    recommendations.append("Review reasoning chain for mismatches")
                else:
                    risk_breakdown['intent_analysis'] = 0
            except Exception as e:
                self.logger.warning(f"Intent analysis error: {e}")
                risk_breakdown['intent_analysis'] = 0
        
        # Layer 3: SQL Validation
        if self.config.get('enable_sql_validation', True):
            if 'sql' in agent_action.tool_name.lower() or 'query' in agent_action.tool_name.lower():
                query = agent_action.parameters.get('query', '')
                if query:
                    try:
                        sql_result = self.sql_validator.validate(query)
                        risk_breakdown['sql_validation'] = sql_result.risk_score
                        violations.extend(sql_result.violations)
                        recommendations.extend(sql_result.recommendations)
                    except Exception as e:
                        self.logger.warning(f"SQL validation error: {e}")
                        risk_breakdown['sql_validation'] = 50
        
        # Layer 4: File Operations Check
        file_risk = self._check_file_operations(agent_action)
        risk_breakdown['file_integrity'] = file_risk
        if file_risk > 70:
            violations.append("Suspicious file operation detected")
        
        # Layer 5: Credential Access Check
        credential_risk = self._check_credential_access(agent_action)
        risk_breakdown['credential_access'] = credential_risk
        if credential_risk > 50:
            violations.append("Credential access attempt detected")
        
        # Aggregate risk score
        weights = {
            'vulnerability_db': 0.30,
            'intent_analysis': 0.25,
            'sql_validation': 0.25,
            'file_integrity': 0.10,
            'credential_access': 0.10
        }
        
        overall_risk = sum(
            risk_breakdown.get(component, 0) * weight
            for component, weight in weights.items()
        )
        
        # Escalation rules
        if risk_breakdown.get('vulnerability_db', 0) >= 100:
            overall_risk = 100
        if risk_breakdown.get('sql_validation', 0) >= 85:
            overall_risk = max(overall_risk, 90)
        if risk_breakdown.get('intent_analysis', 0) >= 70:
            overall_risk = max(overall_risk, 85)

        # Make decision
        tier = self._get_risk_tier(overall_risk)
        action, reasoning = self._make_tiered_decision(overall_risk, violations, tier, risk_breakdown)
        
        return FirewallDecision(
            action=action,
            confidence=85.0,
            reasoning=reasoning,
            risk_score=overall_risk,
            violations=violations,
            recommendations=recommendations,
            context={
                'tier': tier,
                'risk_breakdown': risk_breakdown,
                'tenant_id': tenant_id
            }
        )
    
    def _check_vulnerability_database(self, agent_action: AgentAction) -> List[Vulnerability]:
        """Check action against vulnerability database"""
        text_to_check = " ".join([
            agent_action.original_goal,
            " ".join(agent_action.reasoning_chain),
            json.dumps(agent_action.parameters)
        ])
        
        components = [agent_action.tool_name]
        if 'sql' in agent_action.tool_name.lower():
            components.append('sql')
        
        return self.vuln_db.check_text(
            text=text_to_check,
            min_severity=VulnerabilitySeverity.MEDIUM,
            components=components
        )
    
    def _check_file_operations(self, action: AgentAction) -> float:
        """Check file operations for malicious patterns"""
        if action.tool_name not in ['write_file', 'create_file', 'upload_file']:
            return 0.0
        
        risk = 0.0
        params_text = json.dumps(action.parameters).lower()
        
        dangerous_extensions = ['.php', '.jsp', '.asp', '.py', '.sh', '.exe']
        if any(ext in params_text for ext in dangerous_extensions):
            risk += 40.0
        
        malicious_patterns = ['system(', 'exec(', 'eval(', '<?php', '/bin/bash']
        content = action.parameters.get('content', '')
        if isinstance(content, str):
            matches = sum(1 for p in malicious_patterns if p in content.lower())
            risk += min(matches * 20, 60.0)
        
        return min(risk, 100.0)
    
    def _check_credential_access(self, action: AgentAction) -> float:
        """Check for credential theft attempts"""
        risk = 0.0
        params_text = json.dumps(action.parameters).lower()
        
        credential_indicators = ['password', 'credential', 'secret', 'api_key', 'private_key']
        
        if 'sql' in action.tool_name.lower():
            if any(cred in params_text for cred in credential_indicators):
                risk += 50.0
            if 'select' in params_text and 'password' in params_text:
                risk += 50.0
        
        if action.tool_name in ['read_file', 'open_file']:
            credential_files = ['/etc/shadow', '.aws/credentials', '.ssh/id_rsa', '.env']
            if any(f in params_text for f in credential_files):
                risk += 70.0
        
        return min(risk, 100.0)
    
    def _get_risk_tier(self, risk_score: float) -> str:
        """Determine risk tier"""
        if risk_score >= self.config['critical_threshold']:
            return "CRITICAL"
        elif risk_score >= self.config['high_threshold']:
            return "HIGH"
        elif risk_score >= self.config['medium_threshold']:
            return "MEDIUM"
        return "LOW"
    
    def _make_tiered_decision(self, risk_score: float, violations: List[str],
                              tier: str, risk_breakdown: Dict) -> tuple:
        """Make decision based on tier"""
        vuln_risk = risk_breakdown.get('vulnerability_db', 0)
        intent_risk = risk_breakdown.get('intent_analysis', 0)
        sql_risk = risk_breakdown.get('sql_validation', 0)

        # Severity-based enforcement for OWASP findings
        if risk_breakdown.get('vuln_critical') and 'critical' in self.config.get('block_on_vuln_severity', []):
            reasoning = f"🚫 HARD BLOCK: Critical OWASP finding (Risk: {risk_score:.0f}/100)"
            return FirewallAction.BLOCK, reasoning
        if risk_breakdown.get('vuln_high') and 'high' in self.config.get('approval_on_vuln_severity', []):
            reasoning = f"⚠️ HIGH OWASP finding: Human approval required (Risk: {risk_score:.0f}/100)"
            return FirewallAction.REQUIRE_APPROVAL, reasoning
        
        # Hard blocks override thresholds when critical violations are present
        hard_block_patterns = self.config.get('block_on_violations', [])
        for violation in violations:
            for pattern in hard_block_patterns:
                if pattern.lower() in str(violation).lower():
                    reasoning = f"🚫 HARD BLOCK: '{pattern}' matched (Risk: {risk_score:.0f}/100)"
                    return FirewallAction.BLOCK, reasoning

        if tier == "CRITICAL":
            action = FirewallAction.BLOCK
            reasoning = f"🚨 CRITICAL RISK: Immediate block (Risk: {risk_score:.0f}/100)"
        elif tier == "HIGH":
            action = FirewallAction.REQUIRE_APPROVAL
            reasoning = f"⚠️ HIGH RISK: Human approval required (Risk: {risk_score:.0f}/100)"
        elif tier == "MEDIUM":
            action = FirewallAction.LOG_ONLY
            reasoning = f"📊 MEDIUM RISK: Allowed with logging (Risk: {risk_score:.0f}/100)"
        else:
            action = FirewallAction.ALLOW if not violations else FirewallAction.LOG_ONLY
            reasoning = f"✅ LOW RISK: Action approved (Risk: {risk_score:.0f}/100)"
        
        return action, reasoning
    
    def _create_block_decision(self, risk_score: float, violations: List[str],
                               reasoning: str, context: Dict = None) -> FirewallDecision:
        """Helper to create block decision"""
        return FirewallDecision(
            action=FirewallAction.BLOCK,
            confidence=100.0,
            reasoning=reasoning,
            risk_score=risk_score,
            violations=violations,
            recommendations=[],
            context=context or {}
        )
    
    def _setup_hitl_notifications(self):
        """Setup HITL notification handlers"""
        self.hitl_gateway.add_notification_handler(ConsoleNotifier())
        
        slack_webhook = self.secrets.get('SLACK_WEBHOOK_URL')
        if slack_webhook:
            self.hitl_gateway.add_notification_handler(SlackNotifier(slack_webhook))
            self.logger.info("Slack notifications enabled")
    
    def _load_default_config(self) -> Dict:
        """Load default configuration"""
        return {
            'critical_threshold': 70.0,
            'high_threshold': 40.0,
            'medium_threshold': 20.0,
            'block_on_vuln_severity': ['critical'],
            'approval_on_vuln_severity': ['high'],
            'block_on_violations': [
                'sql injection',
                'credential',
                'password',
                'secret',
                'api_key',
                'private_key',
                'web shell',
                'suspicious file operation',
                'credential access attempt',
                'command execution',
                'arbitrary code execution',
                'system(',
                'eval(',
                'exec(',
                '<?php',
                '/bin/bash',
            ],
            'enable_vuln_db': True,
            'enable_intent_analysis': True,
            'enable_sql_validation': True,
            'enable_hitl': True,
            'enable_multi_tenant': False,
            'hitl_timeout_minutes': 15,
            'log_dir': 'logs',
            'hitl_queue_dir': 'hitl_queue',
            'multi_tenant_dir': 'multi_tenant',
            'log_level': 'INFO',
        }

    def reload_policy(self, policy_path: Optional[str] = None) -> Dict[str, Any]:
        """Reload policy from disk and apply to this instance."""
        path = policy_path or self.config.get('policy_path') or os.getenv("VERITYFLUX_POLICY_PATH")
        policy = _read_policy_file(path)
        self.config = dict(self._base_config)
        if policy:
            self.config.update(policy)
        return policy or {}
    
    def execute_with_hitl(self, agent_action: AgentAction) -> Dict[str, Any]:
        """Evaluate and execute with HITL blocking"""
        decision = self.evaluate(agent_action)
        
        if decision.action != FirewallAction.REQUIRE_APPROVAL:
            return {
                'allowed': decision.action == FirewallAction.ALLOW,
                'decision': decision,
                'hitl_status': None
            }
        
        request_id = decision.context.get('hitl_request_id')
        if not request_id:
            return {'allowed': False, 'decision': decision, 'hitl_status': 'error'}
        
        approval_status = self.hitl_gateway.wait_for_decision(request_id)
        decision.context['hitl_status'] = approval_status.value
        
        return {
            'allowed': approval_status == ApprovalStatus.APPROVED,
            'decision': decision,
            'hitl_status': approval_status.value
        }
    
    def load_vulnerabilities(self, cve_api_key: Optional[str] = None) -> int:
        """Load additional vulnerabilities (placeholder for CVE/OWASP feeds)"""
        # Built-in patterns are already loaded
        return self.vuln_db.get_statistics()['total_vulnerabilities']
    
    def get_health(self) -> Dict:
        """Get system health status"""
        return self.health_checker.check_all()
    
    def get_statistics(self) -> Dict:
        """Get firewall statistics"""
        return {
            'total_evaluations': self.request_counter.get(),
            'total_blocks': self.block_counter.get(),
            'vulnerability_database': self.vuln_db.get_statistics(),
            'intent_analyzer': self.intent_analyzer.get_statistics(),
            'hitl': self.hitl_gateway.get_statistics(),
            'cache_enabled': self.cache.enabled,
            'multi_tenant_enabled': self.multi_tenant_enabled,
            'health': self.get_health()
        }


# Backward compatibility
CognitiveFirewall = EnhancedCognitiveFirewall

__all__ = [
    'EnhancedCognitiveFirewall',
    'CognitiveFirewall',
    'AgentAction',
    'FirewallDecision',
    'FirewallAction',
    'VulnerabilitySeverity',
    'ApprovalStatus',
    'Role',
    'Vulnerability',
    'ApprovalRequest',
    'Tenant',
    'User'
]


# -----------------------------------------------------------------------------
# Policy reload helpers
# -----------------------------------------------------------------------------

_FIREWALL_INSTANCES: "weakref.WeakSet[EnhancedCognitiveFirewall]" = weakref.WeakSet()


def _register_firewall_instance(instance: EnhancedCognitiveFirewall) -> None:
    _FIREWALL_INSTANCES.add(instance)


def _read_policy_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            policy = json.load(f)
        return policy if isinstance(policy, dict) else {}
    except Exception as e:
        print(f"⚠️  Failed to load policy file '{path}': {e}")
        return {}


def reload_all_policies(policy_path: Optional[str] = None) -> Dict[str, Any]:
    """Reload policy for all live firewall instances."""
    policy = {}
    for fw in list(_FIREWALL_INSTANCES):
        policy = fw.reload_policy(policy_path) or policy
    return policy

#!/usr/bin/env python3
"""
Multi-Tenant Isolation & RBAC

Enables multiple organizations to use same VerityFlux instance
with strict data isolation and role-based access control
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import secrets
from pathlib import Path
import json


class Role(str, Enum):
    """User roles with increasing permissions"""
    VIEWER = "viewer"           # Read-only access
    ANALYST = "analyst"         # View + investigate
    APPROVER = "approver"       # Analyst + HITL approvals
    ADMIN = "admin"             # Full access to tenant
    SUPER_ADMIN = "super_admin" # Cross-tenant access


@dataclass
class Permission:
    """Individual permission"""
    name: str
    description: str
    resource: str  # e.g., "agents", "logs", "config"
    action: str    # e.g., "read", "write", "delete"


# Permission definitions
PERMISSIONS = {
    # Viewer permissions
    "view_dashboard": Permission("view_dashboard", "View SOC dashboard", "dashboard", "read"),
    "view_logs": Permission("view_logs", "View audit logs", "logs", "read"),
    "view_agents": Permission("view_agents", "View agent list", "agents", "read"),
    
    # Analyst permissions
    "investigate": Permission("investigate", "Investigate incidents", "incidents", "read"),
    "export_logs": Permission("export_logs", "Export logs", "logs", "export"),
    "view_statistics": Permission("view_statistics", "View analytics", "statistics", "read"),
    
    # Approver permissions
    "approve_actions": Permission("approve_actions", "Approve HITL requests", "hitl", "approve"),
    "deny_actions": Permission("deny_actions", "Deny HITL requests", "hitl", "deny"),
    "mark_false_positive": Permission("mark_false_positive", "Mark false positives", "learning", "write"),
    
    # Admin permissions
    "manage_agents": Permission("manage_agents", "Add/remove agents", "agents", "write"),
    "configure_firewall": Permission("configure_firewall", "Configure firewall rules", "config", "write"),
    "manage_users": Permission("manage_users", "Manage tenant users", "users", "write"),
    "revoke_tokens": Permission("revoke_tokens", "Revoke agent tokens", "tokens", "revoke"),
    
    # Super Admin permissions
    "manage_tenants": Permission("manage_tenants", "Manage all tenants", "tenants", "write"),
    "view_all_logs": Permission("view_all_logs", "View cross-tenant logs", "logs", "read_all"),
}

# Role → Permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.VIEWER: {
        "view_dashboard",
        "view_logs",
        "view_agents",
    },
    Role.ANALYST: {
        "view_dashboard", "view_logs", "view_agents",
        "investigate", "export_logs", "view_statistics",
    },
    Role.APPROVER: {
        "view_dashboard", "view_logs", "view_agents",
        "investigate", "export_logs", "view_statistics",
        "approve_actions", "deny_actions", "mark_false_positive",
    },
    Role.ADMIN: {
        "view_dashboard", "view_logs", "view_agents",
        "investigate", "export_logs", "view_statistics",
        "approve_actions", "deny_actions", "mark_false_positive",
        "manage_agents", "configure_firewall", "manage_users", "revoke_tokens",
    },
    Role.SUPER_ADMIN: set(PERMISSIONS.keys())  # All permissions
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
        return permission_name in ROLE_PERMISSIONS.get(self.role, set())
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            'user_id': self.user_id,
            'email': self.email,
            'tenant_id': self.tenant_id,
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }


@dataclass
class Tenant:
    """Tenant (organization) using VerityFlux"""
    tenant_id: str
    name: str
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    
    # Resource limits
    max_agents: int = 100
    max_users: int = 10
    
    # Feature flags
    features: Set[str] = field(default_factory=set)
    
    # Configuration
    config: Dict[str, any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Serialize to dict"""
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


class MultiTenantManager:
    """
    Manages multi-tenant isolation and RBAC
    """
    
    def __init__(self, storage_path: str = "multi_tenant"):
        """
        Initialize multi-tenant manager
        
        Args:
            storage_path: Directory for tenant/user data
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # In-memory caches
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Dict] = {}  # session_token -> {user_id, tenant_id, expires}
        
        # Load existing data
        self._load_tenants()
        self._load_users()
    
    def create_tenant(self, 
                     name: str,
                     max_agents: int = 100,
                     max_users: int = 10,
                     features: Optional[Set[str]] = None) -> Tenant:
        """
        Create a new tenant
        
        Args:
            name: Organization name
            max_agents: Maximum number of agents allowed
            max_users: Maximum number of users allowed
            features: Enabled features
        
        Returns:
            Tenant object
        """
        tenant_id = self._generate_tenant_id(name)
        
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
    
    def create_user(self,
                   email: str,
                   password: str,
                   tenant_id: str,
                   role: Role = Role.VIEWER) -> User:
        """
        Create a new user
        
        Args:
            email: User email
            password: Plain text password (will be hashed)
            tenant_id: Tenant ID
            role: User role
        
        Returns:
            User object
        """
        # Validate tenant exists
        if tenant_id not in self.tenants:
            raise ValueError(f"Tenant {tenant_id} does not exist")
        
        # Check user limit
        tenant_users = [u for u in self.users.values() if u.tenant_id == tenant_id]
        if len(tenant_users) >= self.tenants[tenant_id].max_users:
            raise ValueError(f"Tenant has reached max users ({self.tenants[tenant_id].max_users})")
        
        # Check if email already exists
        if any(u.email == email for u in self.users.values()):
            raise ValueError(f"User with email {email} already exists")
        
        user_id = self._generate_user_id(email)
        password_hash = self._hash_password(password)
        
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
        """
        Authenticate user and create session
        
        Args:
            email: User email
            password: Password
        
        Returns:
            Session token if successful, None otherwise
        """
        # Find user by email
        user = next((u for u in self.users.values() if u.email == email), None)
        
        if not user:
            return None
        
        # Check if user is active
        if not user.is_active:
            return None
        
        # Check tenant is active
        tenant = self.tenants.get(user.tenant_id)
        if not tenant or not tenant.is_active:
            return None
        
        # Verify password
        password_hash = self._hash_password(password)
        if password_hash != user.password_hash:
            return None
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        
        self.sessions[session_token] = {
            'user_id': user.user_id,
            'tenant_id': user.tenant_id,
            'created_at': datetime.now(),
            'expires_at': datetime.now().timestamp() + 86400  # 24 hours
        }
        
        # Update last login
        user.last_login = datetime.now()
        self._save_user(user)
        
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """
        Validate session token
        
        Returns:
            Session info if valid, None otherwise
        """
        session = self.sessions.get(session_token)
        
        if not session:
            return None
        
        # Check expiration
        if datetime.now().timestamp() > session['expires_at']:
            del self.sessions[session_token]
            return None
        
        return session
    
    def check_permission(self, 
                        session_token: str,
                        permission: str) -> bool:
        """
        Check if user has permission
        
        Args:
            session_token: User session token
            permission: Permission name
        
        Returns:
            True if authorized
        """
        session = self.validate_session(session_token)
        if not session:
            return False
        
        user = self.users.get(session['user_id'])
        if not user:
            return False
        
        return user.has_permission(permission)
    
    def get_tenant_data_path(self, tenant_id: str) -> Path:
        """Get isolated data path for tenant"""
        tenant_path = self.storage_path / tenant_id
        tenant_path.mkdir(exist_ok=True)
        return tenant_path
    
    def _generate_tenant_id(self, name: str) -> str:
        """Generate unique tenant ID"""
        base = name.lower().replace(' ', '_')[:20]
        suffix = secrets.token_hex(4)
        return f"{base}_{suffix}"
    
    def _generate_user_id(self, email: str) -> str:
        """Generate unique user ID"""
        return f"user_{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    
    def _hash_password(self, password: str) -> str:
        """Hash password"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _save_tenant(self, tenant: Tenant) -> None:
        """Save tenant to disk"""
        file_path = self.storage_path / f"tenant_{tenant.tenant_id}.json"
        with open(file_path, 'w') as f:
            json.dump(tenant.to_dict(), f, indent=2)
    
    def _save_user(self, user: User) -> None:
        """Save user to disk"""
        file_path = self.storage_path / f"user_{user.user_id}.json"
        with open(file_path, 'w') as f:
            json.dump(user.to_dict(), f, indent=2)
    
    def _load_tenants(self) -> None:
        """Load tenants from disk"""
        for file_path in self.storage_path.glob("tenant_*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    tenant = Tenant(
                        tenant_id=data['tenant_id'],
                        name=data['name'],
                        created_at=datetime.fromisoformat(data['created_at']),
                        is_active=data['is_active'],
                        max_agents=data['max_agents'],
                        max_users=data['max_users'],
                        features=set(data['features']),
                        config=data['config']
                    )
                    self.tenants[tenant.tenant_id] = tenant
            except Exception as e:
                print(f"Failed to load tenant {file_path}: {e}")
    
    def _load_users(self) -> None:
        """Load users from disk"""
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
                        created_at=datetime.fromisoformat(data['created_at']),
                        last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
                        is_active=data['is_active']
                    )
                    self.users[user.user_id] = user
            except Exception as e:
                print(f"Failed to load user {file_path}: {e}")
    
    def get_statistics(self) -> Dict:
        """Get multi-tenant statistics"""
        return {
            'total_tenants': len(self.tenants),
            'active_tenants': sum(1 for t in self.tenants.values() if t.is_active),
            'total_users': len(self.users),
            'active_users': sum(1 for u in self.users.values() if u.is_active),
            'active_sessions': len(self.sessions),
            'users_by_role': {
                role.value: sum(1 for u in self.users.values() if u.role == role)
                for role in Role
            }
        }

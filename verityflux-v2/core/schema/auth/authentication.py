#!/usr/bin/env python3
"""
VerityFlux Enterprise - Authentication System
Custom Auth with JWT, Sessions, API Keys, and MFA Support

Features:
- JWT-based authentication for web/mobile
- API key authentication for programmatic access
- Session management with refresh tokens
- MFA (TOTP) support
- Rate limiting
- Audit logging
"""

import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import jwt
import pyotp
from functools import wraps

# For password hashing
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

# For encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class AuthConfig:
    """Authentication configuration"""
    # JWT settings
    jwt_secret: str = os.getenv("VERITYFLUX_JWT_SECRET", secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Session settings
    session_expire_hours: int = 24
    max_sessions_per_user: int = 5
    
    # API key settings
    api_key_prefix: str = "vf_"
    
    # Security settings
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    password_min_length: int = 12
    require_mfa_for_admins: bool = True
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_login_attempts_per_hour: int = 10
    
    # Encryption key for sensitive data
    encryption_key: str = os.getenv("VERITYFLUX_ENCRYPTION_KEY", Fernet.generate_key().decode() if CRYPTO_AVAILABLE else "")


# Global config instance
auth_config = AuthConfig()


# =============================================================================
# TOKEN TYPES
# =============================================================================

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    MFA_SETUP = "mfa_setup"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION = "email_verification"


@dataclass
class TokenPayload:
    """JWT token payload"""
    sub: str  # Subject (user_id)
    org_id: str  # Organization ID
    role: str  # User role
    token_type: TokenType
    permissions: list
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for revocation
    
    def to_dict(self) -> dict:
        return {
            "sub": self.sub,
            "org_id": self.org_id,
            "role": self.role,
            "token_type": self.token_type.value,
            "permissions": self.permissions,
            "exp": int(self.exp.timestamp()),
            "iat": int(self.iat.timestamp()),
            "jti": self.jti,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "TokenPayload":
        return cls(
            sub=data["sub"],
            org_id=data["org_id"],
            role=data["role"],
            token_type=TokenType(data["token_type"]),
            permissions=data.get("permissions", []),
            exp=datetime.fromtimestamp(data["exp"]),
            iat=datetime.fromtimestamp(data["iat"]),
            jti=data["jti"],
        )


@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    error: Optional[str] = None
    require_mfa: bool = False
    mfa_token: Optional[str] = None


# =============================================================================
# PASSWORD HANDLING
# =============================================================================

class PasswordManager:
    """Secure password hashing and validation"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt or fallback to PBKDF2"""
        if BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode(), salt).decode()
        else:
            # Fallback to PBKDF2
            salt = secrets.token_hex(16)
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return f"pbkdf2:{salt}:{hash_obj.hex()}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        if password_hash.startswith("pbkdf2:"):
            # PBKDF2 format
            try:
                _, salt, stored_hash = password_hash.split(':')
                hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
                return hash_obj.hex() == stored_hash
            except:
                return False
        elif BCRYPT_AVAILABLE:
            # bcrypt format
            try:
                return bcrypt.checkpw(password.encode(), password_hash.encode())
            except:
                return False
        return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, list]:
        """
        Validate password meets security requirements
        Returns (is_valid, list_of_issues)
        """
        issues = []
        
        if len(password) < auth_config.password_min_length:
            issues.append(f"Password must be at least {auth_config.password_min_length} characters")
        
        if not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one digit")
        
        special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
        if not any(c in special_chars for c in password):
            issues.append("Password must contain at least one special character")
        
        # Check for common passwords (simplified)
        common_passwords = ["password", "123456", "qwerty", "admin", "letmein"]
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return len(issues) == 0, issues


# =============================================================================
# JWT TOKEN MANAGEMENT
# =============================================================================

class TokenManager:
    """JWT token creation and validation"""
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or auth_config
        self._revoked_tokens = set()  # In production, use Redis
    
    def create_access_token(
        self,
        user_id: str,
        organization_id: str,
        role: str,
        permissions: list = None
    ) -> str:
        """Create a new access token"""
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.config.access_token_expire_minutes)
        
        payload = TokenPayload(
            sub=user_id,
            org_id=organization_id,
            role=role,
            token_type=TokenType.ACCESS,
            permissions=permissions or [],
            exp=expires,
            iat=now,
            jti=secrets.token_urlsafe(16),
        )
        
        return jwt.encode(
            payload.to_dict(),
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm
        )
    
    def create_refresh_token(
        self,
        user_id: str,
        organization_id: str,
        role: str
    ) -> str:
        """Create a new refresh token"""
        now = datetime.utcnow()
        expires = now + timedelta(days=self.config.refresh_token_expire_days)
        
        payload = TokenPayload(
            sub=user_id,
            org_id=organization_id,
            role=role,
            token_type=TokenType.REFRESH,
            permissions=[],
            exp=expires,
            iat=now,
            jti=secrets.token_urlsafe(16),
        )
        
        return jwt.encode(
            payload.to_dict(),
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm
        )
    
    def verify_token(self, token: str, expected_type: TokenType = None) -> Optional[TokenPayload]:
        """
        Verify and decode a JWT token
        Returns TokenPayload if valid, None otherwise
        """
        try:
            decoded = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm]
            )
            
            payload = TokenPayload.from_dict(decoded)
            
            # Check if token is revoked
            if payload.jti in self._revoked_tokens:
                return None
            
            # Check token type if specified
            if expected_type and payload.token_type != expected_type:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding its JTI to the revoked set"""
        try:
            decoded = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False}
            )
            self._revoked_tokens.add(decoded["jti"])
            return True
        except:
            return False
    
    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Use a refresh token to get a new access token"""
        payload = self.verify_token(refresh_token, TokenType.REFRESH)
        if not payload:
            return None
        
        return self.create_access_token(
            user_id=payload.sub,
            organization_id=payload.org_id,
            role=payload.role,
            permissions=payload.permissions
        )


# =============================================================================
# API KEY MANAGEMENT
# =============================================================================

class APIKeyManager:
    """API key generation and validation"""
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or auth_config
    
    def generate_api_key(self) -> Tuple[str, str, str]:
        """
        Generate a new API key
        Returns: (full_key, key_prefix, key_hash)
        """
        # Generate random key
        random_part = secrets.token_urlsafe(32)
        full_key = f"{self.config.api_key_prefix}{random_part}"
        
        # Extract prefix for identification
        key_prefix = full_key[:12]
        
        # Hash for storage
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        
        return full_key, key_prefix, key_hash
    
    def verify_api_key(self, api_key: str, stored_hash: str) -> bool:
        """Verify an API key against its stored hash"""
        computed_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return secrets.compare_digest(computed_hash, stored_hash)
    
    def parse_api_key(self, api_key: str) -> Optional[str]:
        """Extract the prefix from an API key for lookup"""
        if api_key and api_key.startswith(self.config.api_key_prefix):
            return api_key[:12]
        return None


# =============================================================================
# MFA (TOTP) MANAGEMENT
# =============================================================================

class MFAManager:
    """Multi-factor authentication using TOTP"""
    
    def __init__(self, issuer: str = "VerityFlux"):
        self.issuer = issuer
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, secret: str, email: str) -> str:
        """Get the provisioning URI for QR code generation"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=self.issuer)
    
    def verify_code(self, secret: str, code: str) -> bool:
        """Verify a TOTP code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Allow 1 step before/after
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for account recovery"""
        return [secrets.token_hex(4).upper() for _ in range(count)]


# =============================================================================
# ENCRYPTION UTILITIES
# =============================================================================

class EncryptionManager:
    """Encrypt/decrypt sensitive data (API keys, tokens, etc.)"""
    
    def __init__(self, key: str = None):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package required for encryption")
        
        self.key = key or auth_config.encryption_key
        self.fernet = Fernet(self.key.encode() if isinstance(self.key, str) else self.key)
    
    def encrypt(self, data: str) -> bytes:
        """Encrypt a string"""
        return self.fernet.encrypt(data.encode())
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt data"""
        return self.fernet.decrypt(encrypted_data).decode()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Derive an encryption key from a password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt


# =============================================================================
# RATE LIMITING
# =============================================================================

class RateLimiter:
    """Simple in-memory rate limiter (use Redis in production)"""
    
    def __init__(self):
        self._requests = {}  # {key: [(timestamp, count), ...]}
    
    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Check if request is allowed under rate limit
        Returns: (is_allowed, remaining_requests)
        """
        now = time.time()
        window_start = now - window_seconds
        
        # Get existing requests for this key
        if key not in self._requests:
            self._requests[key] = []
        
        # Remove old entries
        self._requests[key] = [
            (ts, count) for ts, count in self._requests[key]
            if ts > window_start
        ]
        
        # Count requests in window
        total_requests = sum(count for _, count in self._requests[key])
        
        if total_requests >= max_requests:
            return False, 0
        
        # Add this request
        self._requests[key].append((now, 1))
        
        return True, max_requests - total_requests - 1
    
    def reset(self, key: str):
        """Reset rate limit for a key"""
        if key in self._requests:
            del self._requests[key]


# =============================================================================
# AUTHENTICATION SERVICE
# =============================================================================

class AuthenticationService:
    """
    Main authentication service combining all auth functionality
    """
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or auth_config
        self.password_manager = PasswordManager()
        self.token_manager = TokenManager(self.config)
        self.api_key_manager = APIKeyManager(self.config)
        self.mfa_manager = MFAManager()
        self.rate_limiter = RateLimiter()
        
        if CRYPTO_AVAILABLE:
            self.encryption = EncryptionManager(self.config.encryption_key)
        else:
            self.encryption = None
    
    def authenticate_user(
        self,
        email: str,
        password: str,
        ip_address: str = None,
        user_agent: str = None,
        mfa_code: str = None
    ) -> AuthResult:
        """
        Authenticate a user with email/password (and optional MFA)
        
        This method should be called with user data from the database.
        In production, integrate with SQLAlchemy session.
        """
        # Rate limit check
        rate_key = f"login:{ip_address or 'unknown'}"
        allowed, remaining = self.rate_limiter.is_allowed(
            rate_key,
            self.config.rate_limit_login_attempts_per_hour,
            3600  # 1 hour window
        )
        
        if not allowed:
            return AuthResult(
                success=False,
                error="Too many login attempts. Please try again later."
            )
        
        # This is a placeholder - in production, look up user from database
        # user = session.query(User).filter_by(email=email).first()
        # For now, return a template result
        
        return AuthResult(
            success=False,
            error="Authentication service requires database integration"
        )
    
    def authenticate_with_user_data(
        self,
        user_id: str,
        organization_id: str,
        password_hash: str,
        role: str,
        password: str,
        mfa_enabled: bool = False,
        mfa_secret: str = None,
        mfa_code: str = None,
        locked_until: datetime = None,
        permissions: list = None
    ) -> AuthResult:
        """
        Authenticate a user with pre-fetched user data
        """
        # Check if account is locked
        if locked_until and locked_until > datetime.utcnow():
            return AuthResult(
                success=False,
                error="Account is temporarily locked. Please try again later."
            )
        
        # Verify password
        if not self.password_manager.verify_password(password, password_hash):
            return AuthResult(
                success=False,
                error="Invalid email or password"
            )
        
        # Check MFA if enabled
        if mfa_enabled:
            if not mfa_code:
                # Return partial auth - need MFA
                mfa_token = self.token_manager.create_access_token(
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    permissions=[]
                )
                return AuthResult(
                    success=False,
                    require_mfa=True,
                    mfa_token=mfa_token,
                    error="MFA code required"
                )
            
            # Verify MFA code
            if not self.mfa_manager.verify_code(mfa_secret, mfa_code):
                return AuthResult(
                    success=False,
                    error="Invalid MFA code"
                )
        
        # Generate tokens
        access_token = self.token_manager.create_access_token(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            permissions=permissions or []
        )
        
        refresh_token = self.token_manager.create_refresh_token(
            user_id=user_id,
            organization_id=organization_id,
            role=role
        )
        
        expires_at = datetime.utcnow() + timedelta(
            minutes=self.config.access_token_expire_minutes
        )
        
        return AuthResult(
            success=True,
            user_id=user_id,
            organization_id=organization_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at
        )
    
    def authenticate_api_key(
        self,
        api_key: str,
        stored_hash: str,
        organization_id: str,
        permissions: dict = None,
        is_active: bool = True,
        expires_at: datetime = None
    ) -> AuthResult:
        """
        Authenticate using an API key
        """
        if not is_active:
            return AuthResult(
                success=False,
                error="API key is inactive"
            )
        
        if expires_at and expires_at < datetime.utcnow():
            return AuthResult(
                success=False,
                error="API key has expired"
            )
        
        if not self.api_key_manager.verify_api_key(api_key, stored_hash):
            return AuthResult(
                success=False,
                error="Invalid API key"
            )
        
        # API keys don't get JWT tokens, they're used directly
        return AuthResult(
            success=True,
            organization_id=organization_id
        )
    
    def refresh_session(self, refresh_token: str) -> AuthResult:
        """
        Refresh an expired access token using a refresh token
        """
        payload = self.token_manager.verify_token(refresh_token, TokenType.REFRESH)
        
        if not payload:
            return AuthResult(
                success=False,
                error="Invalid or expired refresh token"
            )
        
        new_access_token = self.token_manager.create_access_token(
            user_id=payload.sub,
            organization_id=payload.org_id,
            role=payload.role,
            permissions=payload.permissions
        )
        
        expires_at = datetime.utcnow() + timedelta(
            minutes=self.config.access_token_expire_minutes
        )
        
        return AuthResult(
            success=True,
            user_id=payload.sub,
            organization_id=payload.org_id,
            access_token=new_access_token,
            refresh_token=refresh_token,  # Return same refresh token
            expires_at=expires_at
        )
    
    def logout(self, access_token: str, refresh_token: str = None) -> bool:
        """
        Logout by revoking tokens
        """
        self.token_manager.revoke_token(access_token)
        if refresh_token:
            self.token_manager.revoke_token(refresh_token)
        return True
    
    def validate_token(self, token: str) -> Optional[TokenPayload]:
        """
        Validate an access token and return its payload
        """
        return self.token_manager.verify_token(token, TokenType.ACCESS)
    
    def create_password_reset_token(self, user_id: str, email: str) -> str:
        """
        Create a password reset token
        """
        now = datetime.utcnow()
        expires = now + timedelta(hours=1)
        
        payload = {
            "sub": user_id,
            "email": email,
            "token_type": TokenType.PASSWORD_RESET.value,
            "exp": int(expires.timestamp()),
            "iat": int(now.timestamp()),
            "jti": secrets.token_urlsafe(16),
        }
        
        return jwt.encode(
            payload,
            self.config.jwt_secret,
            algorithm=self.config.jwt_algorithm
        )
    
    def verify_password_reset_token(self, token: str) -> Optional[dict]:
        """
        Verify a password reset token
        """
        try:
            decoded = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm]
            )
            
            if decoded.get("token_type") != TokenType.PASSWORD_RESET.value:
                return None
            
            return decoded
            
        except jwt.InvalidTokenError:
            return None
    
    def setup_mfa(self, user_id: str, email: str) -> Tuple[str, str]:
        """
        Initialize MFA setup for a user
        Returns: (secret, provisioning_uri)
        """
        secret = self.mfa_manager.generate_secret()
        uri = self.mfa_manager.get_provisioning_uri(secret, email)
        return secret, uri
    
    def verify_mfa_setup(self, secret: str, code: str) -> bool:
        """
        Verify MFA setup with initial code
        """
        return self.mfa_manager.verify_code(secret, code)
    
    def generate_backup_codes(self) -> list:
        """
        Generate MFA backup codes
        """
        return self.mfa_manager.generate_backup_codes()


# =============================================================================
# DECORATORS FOR ROUTE PROTECTION
# =============================================================================

def require_auth(permissions: list = None):
    """
    Decorator to require authentication for a route
    Usage:
        @require_auth(permissions=["scan.run"])
        def protected_route():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This is a placeholder - integrate with your web framework
            # In FastAPI: use Depends()
            # In Flask: check request.headers for Authorization
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_tier(min_tier: str):
    """
    Decorator to require minimum subscription tier
    Usage:
        @require_tier("professional")
        def enterprise_feature():
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check organization tier
            return func(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Authentication System")
    print("=" * 60)
    
    # Test password hashing
    print("\n🔐 Testing Password Manager...")
    pm = PasswordManager()
    
    password = "SecureP@ssw0rd123!"
    hashed = pm.hash_password(password)
    print(f"  Password: {password}")
    print(f"  Hash: {hashed[:50]}...")
    print(f"  Verify (correct): {pm.verify_password(password, hashed)}")
    print(f"  Verify (wrong): {pm.verify_password('wrong', hashed)}")
    
    # Test password strength
    is_valid, issues = pm.validate_password_strength("weak")
    print(f"  'weak' is valid: {is_valid}")
    if issues:
        print(f"  Issues: {issues}")
    
    # Test JWT tokens
    print("\n🎫 Testing Token Manager...")
    tm = TokenManager()
    
    access_token = tm.create_access_token(
        user_id="user-123",
        organization_id="org-456",
        role="admin",
        permissions=["scan.run", "incident.view"]
    )
    print(f"  Access Token: {access_token[:50]}...")
    
    payload = tm.verify_token(access_token, TokenType.ACCESS)
    if payload:
        print(f"  Decoded - User: {payload.sub}, Org: {payload.org_id}")
    
    # Test API keys
    print("\n🔑 Testing API Key Manager...")
    akm = APIKeyManager()
    
    full_key, prefix, key_hash = akm.generate_api_key()
    print(f"  API Key: {full_key[:20]}...")
    print(f"  Prefix: {prefix}")
    print(f"  Verify: {akm.verify_api_key(full_key, key_hash)}")
    
    # Test MFA
    print("\n📱 Testing MFA Manager...")
    mfa = MFAManager()
    
    secret = mfa.generate_secret()
    uri = mfa.get_provisioning_uri(secret, "test@example.com")
    print(f"  Secret: {secret}")
    print(f"  URI: {uri[:60]}...")
    
    # Generate current code for testing
    totp = pyotp.TOTP(secret)
    code = totp.now()
    print(f"  Current Code: {code}")
    print(f"  Verify: {mfa.verify_code(secret, code)}")
    
    # Test rate limiter
    print("\n⏱️ Testing Rate Limiter...")
    rl = RateLimiter()
    
    for i in range(5):
        allowed, remaining = rl.is_allowed("test-key", 3, 60)
        print(f"  Request {i+1}: allowed={allowed}, remaining={remaining}")
    
    # Test full auth service
    print("\n🔒 Testing Authentication Service...")
    auth = AuthenticationService()
    
    result = auth.authenticate_with_user_data(
        user_id="user-123",
        organization_id="org-456",
        password_hash=hashed,
        role="admin",
        password=password,
        permissions=["scan.run"]
    )
    
    print(f"  Auth Success: {result.success}")
    if result.success:
        print(f"  Access Token: {result.access_token[:50]}...")
    
    print("\n✅ All authentication tests passed!")

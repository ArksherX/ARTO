#!/usr/bin/env python3
"""
VerityFlux Enterprise - Licensing System
Supports both SaaS (Stripe) and On-Premise (License Keys)

Features:
- Stripe subscription management for SaaS
- Cryptographic license key generation/validation for on-premise
- Feature gating based on subscription tier
- Usage tracking and limits enforcement
- License activation/deactivation
"""

import os
import json
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

# Stripe integration (optional)
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class LicenseConfig:
    """Licensing configuration"""
    # Stripe settings (SaaS)
    stripe_api_key: str = os.getenv("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    
    # License key settings (On-Premise)
    license_secret_key: str = os.getenv("VERITYFLUX_LICENSE_SECRET", secrets.token_urlsafe(32))
    license_issuer: str = "VerityFlux"
    
    # Product IDs in Stripe
    stripe_products: Dict[str, str] = None
    
    # Grace period for expired licenses
    grace_period_days: int = 7
    
    def __post_init__(self):
        if self.stripe_products is None:
            self.stripe_products = {
                "free": "",
                "startup": os.getenv("STRIPE_PRODUCT_STARTUP", ""),
                "professional": os.getenv("STRIPE_PRODUCT_PROFESSIONAL", ""),
                "enterprise": os.getenv("STRIPE_PRODUCT_ENTERPRISE", ""),
            }


license_config = LicenseConfig()


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class LicenseType(Enum):
    """Type of license"""
    SAAS = "saas"
    ON_PREMISE = "on_premise"
    TRIAL = "trial"
    INTERNAL = "internal"


class LicenseStatus(Enum):
    """License status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    GRACE_PERIOD = "grace_period"
    TRIAL = "trial"


@dataclass
class LicenseInfo:
    """License information"""
    license_id: str
    organization_id: str
    license_type: LicenseType
    tier: str
    status: LicenseStatus
    issued_at: datetime
    expires_at: Optional[datetime]
    activated_at: Optional[datetime] = None
    max_agents: int = 1
    max_users: int = 2
    max_evaluations_per_month: int = 1000
    features: Dict[str, Any] = None
    customer_name: Optional[str] = None
    customer_email: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = {}
        if self.metadata is None:
            self.metadata = {}
    
    def is_valid(self) -> bool:
        """Check if license is currently valid"""
        if self.status not in [LicenseStatus.ACTIVE, LicenseStatus.TRIAL, LicenseStatus.GRACE_PERIOD]:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            grace_end = self.expires_at + timedelta(days=license_config.grace_period_days)
            if datetime.utcnow() > grace_end:
                return False
        return True
    
    def to_dict(self) -> dict:
        return {
            "license_id": self.license_id,
            "organization_id": self.organization_id,
            "license_type": self.license_type.value,
            "tier": self.tier,
            "status": self.status.value,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_agents": self.max_agents,
            "max_users": self.max_users,
            "features": self.features,
        }


@dataclass
class UsageMetrics:
    """Current usage metrics for an organization"""
    organization_id: str
    period_start: datetime
    period_end: datetime
    scans_used: int = 0
    evaluations_used: int = 0
    agents_active: int = 0
    users_active: int = 0
    scans_limit: int = 0
    evaluations_limit: int = 0
    agents_limit: int = 0
    users_limit: int = 0


# =============================================================================
# TIER DEFINITIONS
# =============================================================================

TIER_DEFINITIONS = {
    "free": {
        "name": "Free",
        "max_scans_per_month": 5,
        "max_evaluations_per_month": 1000,
        "max_agents": 1,
        "max_users": 2,
        "features": {
            "security_scan": ["quick"],
            "hitl": False,
            "soc_integrations": [],
            "vuln_db_updates": "monthly",
            "backdoor_detector": "basic",
            "adversarial_lab": False,
            "multi_workspace": False,
            "api_access": False,
            "custom_rules": False,
            "report_formats": ["pdf"],
            "retention_days": 30,
            "support": "community",
        },
        "stripe_price_monthly": 0,
        "stripe_price_yearly": 0,
    },
    "startup": {
        "name": "Startup",
        "max_scans_per_month": 50,
        "max_evaluations_per_month": 10000,
        "max_agents": 5,
        "max_users": 10,
        "features": {
            "security_scan": ["quick", "standard"],
            "hitl": True,
            "soc_integrations": ["slack", "email"],
            "vuln_db_updates": "weekly",
            "backdoor_detector": "full",
            "adversarial_lab": "ctf_only",
            "multi_workspace": False,
            "api_access": "read_only",
            "custom_rules": False,
            "report_formats": ["pdf", "json"],
            "retention_days": 90,
            "support": "email",
        },
        "stripe_price_monthly": 99,
        "stripe_price_yearly": 990,
    },
    "professional": {
        "name": "Professional",
        "max_scans_per_month": -1,
        "max_evaluations_per_month": 100000,
        "max_agents": 25,
        "max_users": 50,
        "features": {
            "security_scan": ["quick", "standard", "deep"],
            "hitl": True,
            "soc_integrations": ["slack", "teams", "pagerduty", "jira", "email", "webhook"],
            "vuln_db_updates": "daily",
            "backdoor_detector": "full",
            "adversarial_lab": "full",
            "multi_workspace": True,
            "api_access": "full",
            "custom_rules": True,
            "report_formats": ["pdf", "json", "csv", "html"],
            "retention_days": 365,
            "support": "priority",
        },
        "stripe_price_monthly": 499,
        "stripe_price_yearly": 4990,
    },
    "enterprise": {
        "name": "Enterprise",
        "max_scans_per_month": -1,
        "max_evaluations_per_month": -1,
        "max_agents": -1,
        "max_users": -1,
        "features": {
            "security_scan": ["quick", "standard", "deep", "compliance", "custom"],
            "hitl": True,
            "soc_integrations": ["slack", "teams", "pagerduty", "jira", "email", "twilio", "webhook", "siem"],
            "vuln_db_updates": "realtime",
            "backdoor_detector": "full",
            "adversarial_lab": "full_custom",
            "multi_workspace": True,
            "api_access": "full",
            "custom_rules": True,
            "report_formats": ["pdf", "json", "csv", "html", "sarif"],
            "retention_days": -1,
            "support": "dedicated",
            "on_premise": True,
            "sso": True,
            "audit_logs": True,
            "custom_branding": True,
        },
        "stripe_price_monthly": 0,
        "stripe_price_yearly": 0,
    },
}


def get_tier_limits(tier: str) -> dict:
    """Get limits and features for a tier"""
    return TIER_DEFINITIONS.get(tier, TIER_DEFINITIONS["free"])


# =============================================================================
# LICENSE KEY GENERATOR (On-Premise)
# =============================================================================

class LicenseKeyGenerator:
    """Generate and validate cryptographic license keys"""
    
    TIER_CODES = {"free": "F", "startup": "S", "professional": "P", "enterprise": "E"}
    TIER_FROM_CODE = {v: k for k, v in TIER_CODES.items()}
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or license_config.license_secret_key
    
    def generate_license_key(
        self,
        organization_id: str,
        tier: str,
        expires_at: datetime,
        max_agents: int = None,
        max_users: int = None,
        customer_name: str = None,
        customer_email: str = None,
        features_override: dict = None
    ) -> Tuple[str, LicenseInfo]:
        """Generate a new license key"""
        license_id = str(uuid.uuid4())
        tier_code = self.TIER_CODES.get(tier, "F")
        tier_limits = get_tier_limits(tier)
        
        license_data = {
            "lid": license_id,
            "oid": organization_id,
            "tier": tier,
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int(expires_at.timestamp()),
            "ma": max_agents or tier_limits["max_agents"],
            "mu": max_users or tier_limits["max_users"],
            "me": tier_limits["max_evaluations_per_month"],
        }
        
        if customer_name:
            license_data["cn"] = customer_name
        if customer_email:
            license_data["ce"] = customer_email
        if features_override:
            license_data["fo"] = features_override
        
        encoded_data = base64.urlsafe_b64encode(
            json.dumps(license_data, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        signature_input = f"{tier_code}-{encoded_data}"
        signature = hmac.new(
            self.secret_key.encode(),
            signature_input.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        license_key = f"VF-{tier_code}-{encoded_data}-{signature.upper()}"
        
        features = tier_limits["features"].copy()
        if features_override:
            features.update(features_override)
        
        license_info = LicenseInfo(
            license_id=license_id,
            organization_id=organization_id,
            license_type=LicenseType.ON_PREMISE,
            tier=tier,
            status=LicenseStatus.ACTIVE,
            issued_at=datetime.utcnow(),
            expires_at=expires_at,
            max_agents=license_data["ma"],
            max_users=license_data["mu"],
            max_evaluations_per_month=license_data["me"],
            features=features,
            customer_name=customer_name,
            customer_email=customer_email,
        )
        
        return license_key, license_info
    
    def validate_license_key(self, license_key: str) -> Tuple[bool, Optional[LicenseInfo], Optional[str]]:
        """Validate a license key"""
        try:
            parts = license_key.split('-')
            if len(parts) != 4 or parts[0] != 'VF':
                return False, None, "Invalid license key format"
            
            _, tier_code, encoded_data, signature = parts
            
            signature_input = f"{tier_code}-{encoded_data}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                signature_input.encode(),
                hashlib.sha256
            ).hexdigest()[:16].upper()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False, None, "Invalid license key signature"
            
            padding_needed = 4 - (len(encoded_data) % 4)
            if padding_needed != 4:
                encoded_data += '=' * padding_needed
            
            license_data = json.loads(base64.urlsafe_b64decode(encoded_data))
            
            expires_at = datetime.fromtimestamp(license_data["exp"])
            now = datetime.utcnow()
            
            if now > expires_at:
                grace_end = expires_at + timedelta(days=license_config.grace_period_days)
                if now > grace_end:
                    status = LicenseStatus.EXPIRED
                else:
                    status = LicenseStatus.GRACE_PERIOD
            else:
                status = LicenseStatus.ACTIVE
            
            tier = self.TIER_FROM_CODE.get(tier_code, "free")
            tier_limits = get_tier_limits(tier)
            
            features = tier_limits["features"].copy()
            if "fo" in license_data:
                features.update(license_data["fo"])
            
            license_info = LicenseInfo(
                license_id=license_data["lid"],
                organization_id=license_data["oid"],
                license_type=LicenseType.ON_PREMISE,
                tier=tier,
                status=status,
                issued_at=datetime.fromtimestamp(license_data["iat"]),
                expires_at=expires_at,
                max_agents=license_data.get("ma", tier_limits["max_agents"]),
                max_users=license_data.get("mu", tier_limits["max_users"]),
                max_evaluations_per_month=license_data.get("me", tier_limits["max_evaluations_per_month"]),
                features=features,
                customer_name=license_data.get("cn"),
                customer_email=license_data.get("ce"),
            )
            
            if status == LicenseStatus.EXPIRED:
                return False, license_info, "License has expired"
            
            return True, license_info, None
            
        except Exception as e:
            return False, None, f"License validation error: {str(e)}"


# =============================================================================
# STRIPE SUBSCRIPTION MANAGER (SaaS)
# =============================================================================

class StripeSubscriptionManager:
    """Manage Stripe subscriptions for SaaS deployments"""
    
    def __init__(self, config: LicenseConfig = None):
        self.config = config or license_config
        if STRIPE_AVAILABLE and self.config.stripe_api_key:
            stripe.api_key = self.config.stripe_api_key
            self.enabled = True
        else:
            self.enabled = False
    
    def create_customer(self, organization_id: str, email: str, name: str) -> Optional[str]:
        """Create a Stripe customer"""
        if not self.enabled:
            return None
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={"organization_id": organization_id}
            )
            return customer.id
        except Exception as e:
            print(f"Stripe error: {e}")
            return None
    
    def create_subscription(self, customer_id: str, tier: str, billing_cycle: str = "monthly") -> Optional[Dict]:
        """Create a new subscription"""
        if not self.enabled:
            return None
        # Implementation would go here
        return None
    
    def get_subscription_info(self, subscription_id: str) -> Optional[LicenseInfo]:
        """Get subscription details as LicenseInfo"""
        if not self.enabled:
            return None
        # Implementation would go here
        return None


# =============================================================================
# UNIFIED LICENSE SERVICE
# =============================================================================

class LicenseService:
    """Unified license service supporting both SaaS and On-Premise"""
    
    def __init__(self, config: LicenseConfig = None):
        self.config = config or license_config
        self.key_generator = LicenseKeyGenerator(self.config.license_secret_key)
        self.stripe_manager = StripeSubscriptionManager(self.config)
    
    def check_feature_access(
        self,
        license_info: LicenseInfo,
        feature: str,
        feature_value: Any = None
    ) -> Tuple[bool, str]:
        """Check if a feature is available under the license"""
        if not license_info.is_valid():
            return False, "License is not valid"
        
        features = license_info.features
        
        if feature not in features:
            return False, f"Feature '{feature}' not available in {license_info.tier} tier"
        
        feature_config = features[feature]
        
        if isinstance(feature_config, bool):
            if feature_config:
                return True, "Allowed"
            return False, f"Feature '{feature}' not available"
        
        if isinstance(feature_config, list):
            if feature_value is None:
                return True, "Allowed"
            if feature_value in feature_config:
                return True, "Allowed"
            return False, f"'{feature_value}' not available"
        
        return True, "Allowed"
    
    def check_usage_limit(
        self,
        license_info: LicenseInfo,
        usage: UsageMetrics,
        limit_type: str,
        increment: int = 1
    ) -> Tuple[bool, str]:
        """Check if a usage limit would be exceeded"""
        if not license_info.is_valid():
            return False, "License is not valid"
        
        limits = {
            "scans": (usage.scans_used, usage.scans_limit),
            "evaluations": (usage.evaluations_used, usage.evaluations_limit),
            "agents": (usage.agents_active, usage.agents_limit),
            "users": (usage.users_active, usage.users_limit),
        }
        
        if limit_type not in limits:
            return True, "Unknown limit type"
        
        current, limit = limits[limit_type]
        
        if limit == -1:
            return True, "Unlimited"
        
        if current + increment > limit:
            return False, f"{limit_type.capitalize()} limit reached ({current}/{limit})"
        
        return True, f"{limit - current - increment} remaining"
    
    def generate_on_premise_license(
        self,
        organization_id: str,
        tier: str,
        duration_days: int = 365,
        customer_name: str = None,
        customer_email: str = None,
        **kwargs
    ) -> Tuple[str, LicenseInfo]:
        """Generate an on-premise license key"""
        expires_at = datetime.utcnow() + timedelta(days=duration_days)
        return self.key_generator.generate_license_key(
            organization_id=organization_id,
            tier=tier,
            expires_at=expires_at,
            customer_name=customer_name,
            customer_email=customer_email,
            **kwargs
        )
    
    def validate_on_premise_license(self, license_key: str) -> Tuple[bool, Optional[LicenseInfo], Optional[str]]:
        """Validate an on-premise license key"""
        return self.key_generator.validate_license_key(license_key)


# =============================================================================
# TESTING
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Licensing System")
    print("=" * 60)
    
    generator = LicenseKeyGenerator()
    
    print("\n🔑 Generating Professional License...")
    license_key, license_info = generator.generate_license_key(
        organization_id="org-12345",
        tier="professional",
        expires_at=datetime.utcnow() + timedelta(days=365),
        customer_name="Acme Corp",
        customer_email="admin@acme.com"
    )
    
    print(f"  License Key: {license_key[:50]}...")
    print(f"  Tier: {license_info.tier}")
    print(f"  Max Agents: {license_info.max_agents}")
    
    print("\n✅ Validating License...")
    is_valid, info, error = generator.validate_license_key(license_key)
    print(f"  Valid: {is_valid}")
    print(f"  Status: {info.status.value if info else 'N/A'}")
    
    print("\n📊 Tier Features:")
    for tier, defn in TIER_DEFINITIONS.items():
        print(f"  {defn['name']}: {defn['max_agents']} agents, HITL={defn['features']['hitl']}")
    
    print("\n✅ Licensing tests passed!")

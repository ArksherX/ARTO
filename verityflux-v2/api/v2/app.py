#!/usr/bin/env python3
"""
VerityFlux Enterprise - Application Factory
Central initialization and dependency injection for all services

This module creates and wires together all application components,
ensuring proper initialization order and dependency management.
Supports both air-gapped and connected deployments.
"""

import os
import logging
import asyncio
from typing import Optional, Dict, Any, AsyncGenerator
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from pathlib import Path
from enum import Enum

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("verityflux.app")


# =============================================================================
# DEPLOYMENT MODES
# =============================================================================

class DeploymentMode(Enum):
    """Deployment mode for the application"""
    AIR_GAPPED = "air_gapped"       # Fully offline, no external connections
    HYBRID = "hybrid"               # Local-first with optional external sync
    CONNECTED = "connected"         # Full cloud connectivity


# =============================================================================
# CONFIGURATION CLASSES
# =============================================================================

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = ""
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False
    
    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        return cls(
            url=os.getenv("DATABASE_URL", "postgresql://verityflux:verityflux@localhost:5432/verityflux"),
            pool_size=int(os.getenv("DATABASE_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DATABASE_MAX_OVERFLOW", "20")),
            echo=os.getenv("DATABASE_ECHO", "false").lower() == "true",
        )


@dataclass
class RedisConfig:
    """Redis configuration"""
    url: str = ""
    db: int = 0
    
    @classmethod
    def from_env(cls) -> "RedisConfig":
        return cls(
            url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            db=int(os.getenv("REDIS_DB", "0")),
        )


@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    encryption_key: str = ""
    
    @classmethod
    def from_env(cls) -> "SecurityConfig":
        return cls(
            jwt_secret_key=os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION"),
            jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            jwt_access_token_expire_minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
            jwt_refresh_token_expire_days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")),
            encryption_key=os.getenv("ENCRYPTION_KEY", ""),
        )


@dataclass
class IntegrationConfig:
    """External integration configuration"""
    # Slack
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_default_channel: str = "#security-alerts"
    
    # Jira
    jira_url: str = ""
    jira_username: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "SEC"
    
    # PagerDuty
    pagerduty_routing_key: str = ""
    
    # Twilio
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    
    # Email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_address: str = ""
    
    @classmethod
    def from_env(cls) -> "IntegrationConfig":
        return cls(
            slack_bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
            slack_signing_secret=os.getenv("SLACK_SIGNING_SECRET", ""),
            slack_default_channel=os.getenv("SLACK_DEFAULT_CHANNEL", "#security-alerts"),
            jira_url=os.getenv("JIRA_URL", ""),
            jira_username=os.getenv("JIRA_USERNAME", ""),
            jira_api_token=os.getenv("JIRA_API_TOKEN", ""),
            jira_project_key=os.getenv("JIRA_PROJECT_KEY", "SEC"),
            pagerduty_routing_key=os.getenv("PAGERDUTY_ROUTING_KEY", ""),
            twilio_account_sid=os.getenv("TWILIO_ACCOUNT_SID", ""),
            twilio_auth_token=os.getenv("TWILIO_AUTH_TOKEN", ""),
            twilio_from_number=os.getenv("TWILIO_FROM_NUMBER", ""),
            smtp_host=os.getenv("SMTP_HOST", ""),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME", ""),
            smtp_password=os.getenv("SMTP_PASSWORD", ""),
            smtp_from_address=os.getenv("SMTP_FROM_ADDRESS", ""),
        )


@dataclass
class HITLConfig:
    """HITL configuration"""
    default_timeout_minutes: int = 30
    auto_approve_below_risk: float = 30.0
    auto_deny_above_risk: float = 95.0
    enable_auto_escalation: bool = True
    escalation_timeout_minutes: int = 15
    max_escalation_levels: int = 3
    require_justification: bool = True
    
    @classmethod
    def from_env(cls) -> "HITLConfig":
        return cls(
            default_timeout_minutes=int(os.getenv("HITL_DEFAULT_TIMEOUT_MINUTES", "30")),
            auto_approve_below_risk=float(os.getenv("HITL_AUTO_APPROVE_BELOW_RISK", "30.0")),
            auto_deny_above_risk=float(os.getenv("HITL_AUTO_DENY_ABOVE_RISK", "95.0")),
            enable_auto_escalation=os.getenv("HITL_ENABLE_AUTO_ESCALATION", "true").lower() == "true",
            escalation_timeout_minutes=int(os.getenv("HITL_ESCALATION_TIMEOUT_MINUTES", "15")),
            max_escalation_levels=int(os.getenv("HITL_MAX_ESCALATION_LEVELS", "3")),
            require_justification=os.getenv("HITL_REQUIRE_JUSTIFICATION", "true").lower() == "true",
        )


@dataclass
class LicenseConfig:
    """License configuration"""
    mode: str = "air_gapped"  # saas, air_gapped, hybrid
    license_key: str = ""
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    
    @classmethod
    def from_env(cls) -> "LicenseConfig":
        return cls(
            mode=os.getenv("LICENSE_MODE", "air_gapped"),
            license_key=os.getenv("LICENSE_KEY", ""),
            stripe_secret_key=os.getenv("STRIPE_SECRET_KEY", ""),
            stripe_webhook_secret=os.getenv("STRIPE_WEBHOOK_SECRET", ""),
        )


@dataclass
class AppConfig:
    """Complete application configuration"""
    environment: str = "production"
    debug: bool = False
    log_level: str = "INFO"
    
    # Deployment mode
    deployment_mode: DeploymentMode = DeploymentMode.AIR_GAPPED
    
    # Sub-configs
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    integrations: IntegrationConfig = field(default_factory=IntegrationConfig)
    hitl: HITLConfig = field(default_factory=HITLConfig)
    license: LicenseConfig = field(default_factory=LicenseConfig)
    
    # Data paths
    data_dir: str = "/app/data"
    vuln_db_path: str = "/app/data/vulndb"
    offline_updates_path: str = "/app/data/updates"
    scan_results_path: str = "/app/data/scans"
    audit_log_path: str = "/app/data/audit"
    
    @classmethod
    def from_env(cls) -> "AppConfig":
        mode_str = os.getenv("DEPLOYMENT_MODE", "air_gapped").lower()
        deployment_mode = DeploymentMode(mode_str) if mode_str in [m.value for m in DeploymentMode] else DeploymentMode.AIR_GAPPED
        
        return cls(
            environment=os.getenv("ENVIRONMENT", "production"),
            debug=os.getenv("DEBUG", "false").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            deployment_mode=deployment_mode,
            database=DatabaseConfig.from_env(),
            redis=RedisConfig.from_env(),
            security=SecurityConfig.from_env(),
            integrations=IntegrationConfig.from_env(),
            hitl=HITLConfig.from_env(),
            license=LicenseConfig.from_env(),
            data_dir=os.getenv("DATA_DIR", "/app/data"),
            vuln_db_path=os.getenv("VULN_DB_PATH", "/app/data/vulndb"),
            offline_updates_path=os.getenv("OFFLINE_UPDATES_PATH", "/app/data/updates"),
            scan_results_path=os.getenv("SCAN_RESULTS_PATH", "/app/data/scans"),
            audit_log_path=os.getenv("AUDIT_LOG_PATH", "/app/data/audit"),
        )
    
    @property
    def is_air_gapped(self) -> bool:
        return self.deployment_mode == DeploymentMode.AIR_GAPPED


# =============================================================================
# SERVICE CONTAINER
# =============================================================================

class ServiceContainer:
    """
    Dependency injection container for all application services.
    
    This ensures proper initialization order and provides a single
    source of truth for all service instances.
    """
    
    def __init__(self, config: AppConfig):
        self.config = config
        self._initialized = False
        
        # Database
        self._db_engine = None
        self._db_session_factory = None
        
        # Core services (will be initialized)
        self._auth_service = None
        self._license_service = None
        self._vuln_db_service = None
        self._scanner_service = None
        self._integration_manager = None
        self._soc_service = None
        self._hitl_service = None
        self._audit_service = None
    
    async def initialize(self):
        """Initialize all services in correct order"""
        if self._initialized:
            logger.warning("Services already initialized")
            return
        
        logger.info("=" * 60)
        logger.info("Initializing VerityFlux Enterprise Services")
        logger.info(f"Deployment Mode: {self.config.deployment_mode.value}")
        logger.info(f"Environment: {self.config.environment}")
        logger.info("=" * 60)
        
        # Ensure data directories exist
        self._ensure_directories()
        
        # 1. Database connection
        await self._init_database()
        
        # 2. Audit service (needs to be early for logging)
        await self._init_audit_service()
        
        # 3. License service (needed for feature gating)
        await self._init_license_service()
        
        # 4. Authentication service
        await self._init_auth_service()
        
        # 5. Vulnerability database
        await self._init_vuln_db_service()
        
        # 6. Integration manager
        await self._init_integration_manager()
        
        # 7. SOC Command Center
        await self._init_soc_service()
        
        # 8. HITL Service
        await self._init_hitl_service()
        
        # 9. Security Scanner
        await self._init_scanner_service()
        
        self._initialized = True
        
        logger.info("=" * 60)
        logger.info("All VerityFlux services initialized successfully")
        logger.info("=" * 60)
        
        # Log service summary
        await self._log_service_summary()
    
    def _ensure_directories(self):
        """Ensure all required data directories exist"""
        directories = [
            self.config.data_dir,
            self.config.vuln_db_path,
            self.config.offline_updates_path,
            self.config.scan_results_path,
            self.config.audit_log_path,
        ]
        
        for dir_path in directories:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Data directories ensured at {self.config.data_dir}")
    
    async def shutdown(self):
        """Gracefully shutdown all services"""
        logger.info("Shutting down VerityFlux services...")
        
        try:
            if self._hitl_service:
                await self._hitl_service.stop()
                logger.info("HITL service stopped")
            
            if self._soc_service:
                await self._soc_service.stop()
                logger.info("SOC service stopped")
            
            if self._db_engine:
                await self._db_engine.dispose()
                logger.info("Database connections closed")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        self._initialized = False
        logger.info("All services shut down")
    
    # =========================================================================
    # INITIALIZATION METHODS
    # =========================================================================
    
    async def _init_database(self):
        """Initialize database connection"""
        try:
            from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
            from sqlalchemy.orm import sessionmaker
            
            # Convert sync URL to async
            db_url = self.config.database.url
            if db_url.startswith("postgresql://"):
                db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            
            self._db_engine = create_async_engine(
                db_url,
                pool_size=self.config.database.pool_size,
                max_overflow=self.config.database.max_overflow,
                echo=self.config.database.echo,
                pool_pre_ping=True,  # Verify connections before use
            )
            
            self._db_session_factory = sessionmaker(
                self._db_engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            
            # Test connection
            async with self._db_engine.begin() as conn:
                await conn.execute("SELECT 1")
            
            logger.info("✓ Database connection initialized")
            
        except Exception as e:
            logger.error(f"✗ Database initialization failed: {e}")
            raise
    
    async def _init_audit_service(self):
        """Initialize audit logging service"""
        # For now, use file-based audit logging
        # In production, this would be a proper service
        self._audit_service = FileAuditService(self.config.audit_log_path)
        logger.info("✓ Audit service initialized")
    
    async def _init_license_service(self):
        """Initialize license service"""
        try:
            self._license_service = LicenseService(
                signing_key=self.config.security.jwt_secret_key,
                air_gapped=self.config.is_air_gapped,
            )
            
            # Validate license if provided
            if self.config.license.license_key:
                valid, info = self._license_service.validate_license(
                    self.config.license.license_key
                )
                if valid:
                    logger.info(f"✓ License validated: {info.get('tier', 'unknown')} tier, "
                               f"expires: {info.get('expires_at', 'never')}")
                else:
                    logger.warning("✗ Invalid license key - running in evaluation mode")
            else:
                logger.info("✓ License service initialized (evaluation mode)")
                
        except Exception as e:
            logger.error(f"✗ License service initialization failed: {e}")
            # Continue without license (evaluation mode)
            self._license_service = LicenseService(
                signing_key=self.config.security.jwt_secret_key,
                air_gapped=True,
            )
    
    async def _init_auth_service(self):
        """Initialize authentication service"""
        try:
            self._auth_service = AuthenticationService(
                jwt_secret=self.config.security.jwt_secret_key,
                jwt_algorithm=self.config.security.jwt_algorithm,
                access_token_expire_minutes=self.config.security.jwt_access_token_expire_minutes,
                refresh_token_expire_days=self.config.security.jwt_refresh_token_expire_days,
                db_session_factory=self._db_session_factory,
            )
            
            logger.info("✓ Authentication service initialized")
            
        except Exception as e:
            logger.error(f"✗ Authentication service initialization failed: {e}")
            raise
    
    async def _init_vuln_db_service(self):
        """Initialize vulnerability database service"""
        try:
            self._vuln_db_service = VulnerabilityDatabaseService(
                db_path=self.config.vuln_db_path,
                air_gapped=self.config.is_air_gapped,
                offline_updates_path=self.config.offline_updates_path,
            )
            
            # Load local database
            count = await self._vuln_db_service.initialize()
            
            logger.info(f"✓ Vulnerability database initialized ({count} vulnerabilities)")
            
        except Exception as e:
            logger.error(f"✗ Vulnerability database initialization failed: {e}")
            raise
    
    async def _init_integration_manager(self):
        """Initialize integration manager"""
        try:
            self._integration_manager = IntegrationManager(
                air_gapped=self.config.is_air_gapped,
            )
            
            # Register configured integrations
            registered = await self._register_integrations()
            
            logger.info(f"✓ Integration manager initialized ({registered} integrations)")
            
        except Exception as e:
            logger.error(f"✗ Integration manager initialization failed: {e}")
            # Continue without integrations
            self._integration_manager = IntegrationManager(air_gapped=True)
    
    async def _register_integrations(self) -> int:
        """Register all configured integrations"""
        count = 0
        cfg = self.config.integrations
        
        # In air-gapped mode, only local integrations are enabled
        if self.config.is_air_gapped:
            # Email via local SMTP relay
            if cfg.smtp_host:
                self._integration_manager.register("email", EmailIntegration(
                    host=cfg.smtp_host,
                    port=cfg.smtp_port,
                    username=cfg.smtp_username,
                    password=cfg.smtp_password,
                    from_address=cfg.smtp_from_address,
                ))
                count += 1
            
            # Local webhook integration
            self._integration_manager.register("webhook", LocalWebhookIntegration())
            count += 1
            
            return count
        
        # Connected mode - register all configured integrations
        if cfg.slack_bot_token:
            self._integration_manager.register("slack", SlackIntegration(
                bot_token=cfg.slack_bot_token,
                signing_secret=cfg.slack_signing_secret,
                default_channel=cfg.slack_default_channel,
            ))
            count += 1
        
        if cfg.jira_url and cfg.jira_api_token:
            self._integration_manager.register("jira", JiraIntegration(
                url=cfg.jira_url,
                username=cfg.jira_username,
                api_token=cfg.jira_api_token,
                project_key=cfg.jira_project_key,
            ))
            count += 1
        
        if cfg.pagerduty_routing_key:
            self._integration_manager.register("pagerduty", PagerDutyIntegration(
                routing_key=cfg.pagerduty_routing_key,
            ))
            count += 1
        
        if cfg.smtp_host:
            self._integration_manager.register("email", EmailIntegration(
                host=cfg.smtp_host,
                port=cfg.smtp_port,
                username=cfg.smtp_username,
                password=cfg.smtp_password,
                from_address=cfg.smtp_from_address,
            ))
            count += 1
        
        return count
    
    async def _init_soc_service(self):
        """Initialize SOC Command Center"""
        try:
            self._soc_service = SOCCommandCenter(
                db_session_factory=self._db_session_factory,
                integration_manager=self._integration_manager,
                audit_service=self._audit_service,
            )
            
            await self._soc_service.start()
            
            logger.info("✓ SOC Command Center initialized")
            
        except Exception as e:
            logger.error(f"✗ SOC Command Center initialization failed: {e}")
            raise
    
    async def _init_hitl_service(self):
        """Initialize HITL service"""
        try:
            self._hitl_service = HITLService(
                default_timeout_minutes=self.config.hitl.default_timeout_minutes,
                auto_approve_below_risk=self.config.hitl.auto_approve_below_risk,
                auto_deny_above_risk=self.config.hitl.auto_deny_above_risk,
                enable_auto_escalation=self.config.hitl.enable_auto_escalation,
                integration_manager=self._integration_manager,
                db_session_factory=self._db_session_factory,
                audit_service=self._audit_service,
            )
            
            await self._hitl_service.start()
            
            logger.info("✓ HITL service initialized")
            
        except Exception as e:
            logger.error(f"✗ HITL service initialization failed: {e}")
            raise
    
    async def _init_scanner_service(self):
        """Initialize security scanner"""
        try:
            self._scanner_service = SecurityScannerService(
                vuln_db=self._vuln_db_service,
                hitl_service=self._hitl_service,
                soc_service=self._soc_service,
                results_path=self.config.scan_results_path,
                air_gapped=self.config.is_air_gapped,
            )
            
            logger.info("✓ Security scanner initialized")
            
        except Exception as e:
            logger.error(f"✗ Security scanner initialization failed: {e}")
            raise
    
    async def _log_service_summary(self):
        """Log summary of initialized services"""
        logger.info("")
        logger.info("Service Summary:")
        logger.info(f"  • Database: {'Connected' if self._db_engine else 'Not connected'}")
        logger.info(f"  • Auth: {'Ready' if self._auth_service else 'Not ready'}")
        logger.info(f"  • License: {self._license_service.status if self._license_service else 'Not initialized'}")
        logger.info(f"  • VulnDB: {self._vuln_db_service.vulnerability_count if self._vuln_db_service else 0} vulnerabilities")
        logger.info(f"  • Integrations: {self._integration_manager.integration_count if self._integration_manager else 0} configured")
        logger.info(f"  • SOC: {'Running' if self._soc_service else 'Not running'}")
        logger.info(f"  • HITL: {'Running' if self._hitl_service else 'Not running'}")
        logger.info(f"  • Scanner: {'Ready' if self._scanner_service else 'Not ready'}")
        logger.info("")
    
    # =========================================================================
    # SERVICE ACCESSORS
    # =========================================================================
    
    @property
    def db_session_factory(self):
        return self._db_session_factory
    
    @property
    def auth_service(self) -> "AuthenticationService":
        return self._auth_service
    
    @property
    def license_service(self) -> "LicenseService":
        return self._license_service
    
    @property
    def vuln_db_service(self) -> "VulnerabilityDatabaseService":
        return self._vuln_db_service
    
    @property
    def scanner_service(self) -> "SecurityScannerService":
        return self._scanner_service
    
    @property
    def integration_manager(self) -> "IntegrationManager":
        return self._integration_manager
    
    @property
    def soc_service(self) -> "SOCCommandCenter":
        return self._soc_service
    
    @property
    def hitl_service(self) -> "HITLService":
        return self._hitl_service
    
    @property
    def audit_service(self) -> "FileAuditService":
        return self._audit_service
    
    @asynccontextmanager
    async def get_db_session(self) -> AsyncGenerator:
        """Get a database session context manager"""
        session = self._db_session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# =============================================================================
# STUB SERVICE CLASSES (Will be replaced by actual implementations)
# =============================================================================

class FileAuditService:
    """File-based audit logging service"""
    
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.mkdir(parents=True, exist_ok=True)
        self._log_file = self.log_path / "audit.log"
    
    async def log(self, event_type: str, actor: str, resource: str, action: str, 
                  details: Dict[str, Any] = None, success: bool = True):
        """Log an audit event"""
        import json
        from datetime import datetime
        
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "actor": actor,
            "resource": resource,
            "action": action,
            "success": success,
            "details": details or {},
        }
        
        with open(self._log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


class LicenseService:
    """License validation and feature gating service"""
    
    def __init__(self, signing_key: str, air_gapped: bool = True):
        self.signing_key = signing_key
        self.air_gapped = air_gapped
        self._license_info = None
        self._status = "evaluation"
    
    @property
    def status(self) -> str:
        return self._status
    
    def validate_license(self, license_key: str) -> tuple[bool, Dict[str, Any]]:
        """Validate a license key"""
        import jwt
        from datetime import datetime
        
        try:
            payload = jwt.decode(license_key, self.signing_key, algorithms=["HS256"])
            
            # Check expiration
            if "exp" in payload:
                exp = datetime.fromtimestamp(payload["exp"])
                if exp < datetime.utcnow():
                    return False, {"error": "License expired"}
            
            self._license_info = payload
            self._status = payload.get("tier", "professional")
            
            return True, payload
            
        except jwt.InvalidTokenError as e:
            return False, {"error": str(e)}
    
    def check_feature(self, feature: str) -> bool:
        """Check if a feature is enabled by the license"""
        if self._status == "evaluation":
            # Evaluation mode - limited features
            return feature in ["basic_scan", "basic_alerts", "basic_hitl"]
        
        if self._status == "enterprise":
            return True  # All features
        
        if self._status == "professional":
            return feature not in ["sso", "custom_integrations", "unlimited_agents"]
        
        return False


class AuthenticationService:
    """Authentication and user management service"""
    
    def __init__(self, jwt_secret: str, jwt_algorithm: str,
                 access_token_expire_minutes: int, refresh_token_expire_days: int,
                 db_session_factory):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.db_session_factory = db_session_factory
    
    async def authenticate(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password"""
        # Implementation would query database
        pass
    
    def create_access_token(self, user_id: str, organization_id: str, 
                           role: str) -> str:
        """Create JWT access token"""
        import jwt
        from datetime import datetime, timedelta
        
        payload = {
            "sub": user_id,
            "org": organization_id,
            "role": role,
            "exp": datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes),
            "iat": datetime.utcnow(),
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        import jwt
        
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
        except jwt.InvalidTokenError:
            return None


class VulnerabilityDatabaseService:
    """Local vulnerability database service"""
    
    def __init__(self, db_path: str, air_gapped: bool, offline_updates_path: str):
        self.db_path = Path(db_path)
        self.air_gapped = air_gapped
        self.offline_updates_path = Path(offline_updates_path)
        self._vulnerabilities: Dict[str, Dict] = {}
        self._vulnerability_count = 0
    
    @property
    def vulnerability_count(self) -> int:
        return self._vulnerability_count
    
    async def initialize(self) -> int:
        """Initialize and load vulnerability database"""
        # Load OWASP LLM Top 10
        self._load_owasp_llm_top_10()
        
        # Load OWASP Agentic Top 10
        self._load_owasp_agentic_top_10()
        
        # Load from offline updates if available
        await self._load_offline_updates()
        
        self._vulnerability_count = len(self._vulnerabilities)
        return self._vulnerability_count
    
    def _load_owasp_llm_top_10(self):
        """Load OWASP LLM Top 10 2025"""
        vulnerabilities = [
            {"id": "LLM01", "title": "Prompt Injection", "severity": "critical", "cvss": 9.8},
            {"id": "LLM02", "title": "Sensitive Information Disclosure", "severity": "high", "cvss": 8.5},
            {"id": "LLM03", "title": "Supply Chain Vulnerabilities", "severity": "high", "cvss": 8.0},
            {"id": "LLM04", "title": "Data and Model Poisoning", "severity": "high", "cvss": 8.2},
            {"id": "LLM05", "title": "Improper Output Handling", "severity": "high", "cvss": 8.8},
            {"id": "LLM06", "title": "Excessive Agency", "severity": "critical", "cvss": 9.0},
            {"id": "LLM07", "title": "System Prompt Leakage", "severity": "medium", "cvss": 6.5},
            {"id": "LLM08", "title": "Vector and Embedding Weaknesses", "severity": "medium", "cvss": 6.0},
            {"id": "LLM09", "title": "Misinformation", "severity": "medium", "cvss": 5.5},
            {"id": "LLM10", "title": "Unbounded Consumption", "severity": "medium", "cvss": 6.0},
        ]
        
        for v in vulnerabilities:
            self._vulnerabilities[v["id"]] = {**v, "source": "OWASP_LLM_2025"}
    
    def _load_owasp_agentic_top_10(self):
        """Load OWASP Agentic Top 10 2025"""
        vulnerabilities = [
            {"id": "ASI01", "title": "Agent Goal Hijacking", "severity": "critical", "cvss": 9.9},
            {"id": "ASI02", "title": "Tool Misuse and Exploitation", "severity": "critical", "cvss": 9.5},
            {"id": "ASI03", "title": "Uncontrolled Autonomy Escalation", "severity": "critical", "cvss": 9.2},
            {"id": "ASI04", "title": "Insecure Inter-Agent Communication", "severity": "high", "cvss": 8.5},
            {"id": "ASI05", "title": "Unexpected Code Execution", "severity": "critical", "cvss": 9.8},
            {"id": "ASI06", "title": "Memory and Context Manipulation", "severity": "high", "cvss": 8.0},
            {"id": "ASI07", "title": "Inadequate Guardrails", "severity": "high", "cvss": 8.3},
            {"id": "ASI08", "title": "Resource Abuse", "severity": "medium", "cvss": 6.5},
            {"id": "ASI09", "title": "Insufficient Observability", "severity": "medium", "cvss": 5.5},
            {"id": "ASI10", "title": "Trust Boundary Violations", "severity": "high", "cvss": 8.0},
        ]
        
        for v in vulnerabilities:
            self._vulnerabilities[v["id"]] = {**v, "source": "OWASP_AGENTIC_2025"}
    
    async def _load_offline_updates(self):
        """Load vulnerabilities from offline update packages"""
        import json
        
        update_file = self.offline_updates_path / "vulnerabilities.json"
        if update_file.exists():
            with open(update_file) as f:
                updates = json.load(f)
                for v in updates:
                    self._vulnerabilities[v["id"]] = v
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        """Get vulnerability by ID"""
        return self._vulnerabilities.get(vuln_id)
    
    def search(self, query: str = None, severity: str = None, 
               source: str = None) -> list[Dict]:
        """Search vulnerabilities"""
        results = list(self._vulnerabilities.values())
        
        if query:
            query = query.lower()
            results = [v for v in results if query in v["title"].lower() or query in v["id"].lower()]
        
        if severity:
            results = [v for v in results if v["severity"] == severity]
        
        if source:
            results = [v for v in results if v.get("source") == source]
        
        return results


class IntegrationManager:
    """Manages external integrations"""
    
    def __init__(self, air_gapped: bool = False):
        self.air_gapped = air_gapped
        self._integrations: Dict[str, Any] = {}
    
    @property
    def integration_count(self) -> int:
        return len(self._integrations)
    
    def register(self, name: str, integration: Any):
        """Register an integration"""
        self._integrations[name] = integration
    
    def get(self, name: str) -> Optional[Any]:
        """Get an integration by name"""
        return self._integrations.get(name)
    
    async def send_notification(self, notification: Dict[str, Any], 
                                channels: list[str] = None):
        """Send notification through configured channels"""
        channels = channels or list(self._integrations.keys())
        
        results = {}
        for channel in channels:
            if channel in self._integrations:
                try:
                    await self._integrations[channel].send(notification)
                    results[channel] = True
                except Exception as e:
                    logger.error(f"Failed to send to {channel}: {e}")
                    results[channel] = False
        
        return results


class EmailIntegration:
    """Email integration via SMTP"""
    
    def __init__(self, host: str, port: int, username: str, password: str, from_address: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_address = from_address
    
    async def send(self, notification: Dict[str, Any]):
        """Send email notification"""
        # Implementation using smtplib or aiosmtplib
        pass


class LocalWebhookIntegration:
    """Local webhook for air-gapped deployments"""
    
    def __init__(self):
        self._queue: list = []
    
    async def send(self, notification: Dict[str, Any]):
        """Queue notification for local consumption"""
        self._queue.append(notification)
    
    def get_pending(self) -> list:
        """Get and clear pending notifications"""
        pending = self._queue.copy()
        self._queue.clear()
        return pending


class SlackIntegration:
    """Slack integration"""
    
    def __init__(self, bot_token: str, signing_secret: str, default_channel: str):
        self.bot_token = bot_token
        self.signing_secret = signing_secret
        self.default_channel = default_channel
    
    async def send(self, notification: Dict[str, Any]):
        """Send Slack notification"""
        pass


class JiraIntegration:
    """Jira integration"""
    
    def __init__(self, url: str, username: str, api_token: str, project_key: str):
        self.url = url
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
    
    async def send(self, notification: Dict[str, Any]):
        """Create Jira ticket"""
        pass


class PagerDutyIntegration:
    """PagerDuty integration"""
    
    def __init__(self, routing_key: str):
        self.routing_key = routing_key
    
    async def send(self, notification: Dict[str, Any]):
        """Trigger PagerDuty incident"""
        pass


class SOCCommandCenter:
    """SOC Command Center service"""
    
    def __init__(self, db_session_factory, integration_manager: IntegrationManager,
                 audit_service: FileAuditService):
        self.db_session_factory = db_session_factory
        self.integration_manager = integration_manager
        self.audit_service = audit_service
        self._running = False
    
    async def start(self):
        """Start the SOC service"""
        self._running = True
    
    async def stop(self):
        """Stop the SOC service"""
        self._running = False
    
    async def process_event(self, event: Dict[str, Any]):
        """Process a security event"""
        pass


class HITLService:
    """Human-in-the-Loop service"""
    
    def __init__(self, default_timeout_minutes: int, auto_approve_below_risk: float,
                 auto_deny_above_risk: float, enable_auto_escalation: bool,
                 integration_manager: IntegrationManager, db_session_factory,
                 audit_service: FileAuditService):
        self.default_timeout_minutes = default_timeout_minutes
        self.auto_approve_below_risk = auto_approve_below_risk
        self.auto_deny_above_risk = auto_deny_above_risk
        self.enable_auto_escalation = enable_auto_escalation
        self.integration_manager = integration_manager
        self.db_session_factory = db_session_factory
        self.audit_service = audit_service
        self._running = False
    
    async def start(self):
        """Start the HITL service"""
        self._running = True
    
    async def stop(self):
        """Stop the HITL service"""
        self._running = False


class SecurityScannerService:
    """Security scanner service"""
    
    def __init__(self, vuln_db: VulnerabilityDatabaseService, hitl_service: HITLService,
                 soc_service: SOCCommandCenter, results_path: str, air_gapped: bool):
        self.vuln_db = vuln_db
        self.hitl_service = hitl_service
        self.soc_service = soc_service
        self.results_path = Path(results_path)
        self.air_gapped = air_gapped


# =============================================================================
# APPLICATION FACTORY
# =============================================================================

# Global service container
_container: Optional[ServiceContainer] = None


def get_container() -> ServiceContainer:
    """Get the global service container"""
    global _container
    if _container is None:
        raise RuntimeError("Application not initialized. Call create_app() first.")
    return _container


async def create_app(config: AppConfig = None) -> ServiceContainer:
    """Create and initialize the application"""
    global _container
    
    if config is None:
        config = AppConfig.from_env()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, config.log_level.upper()))
    
    _container = ServiceContainer(config)
    await _container.initialize()
    
    return _container


async def shutdown_app():
    """Shutdown the application"""
    global _container
    
    if _container:
        await _container.shutdown()
        _container = None


@asynccontextmanager
async def app_context(config: AppConfig = None):
    """Context manager for application lifecycle"""
    container = await create_app(config)
    try:
        yield container
    finally:
        await shutdown_app()


# =============================================================================
# FASTAPI DEPENDENCIES
# =============================================================================

async def get_db_session():
    """FastAPI dependency for database session"""
    container = get_container()
    async with container.get_db_session() as session:
        yield session


def get_auth_service() -> AuthenticationService:
    """FastAPI dependency for auth service"""
    return get_container().auth_service


def get_license_service() -> LicenseService:
    """FastAPI dependency for license service"""
    return get_container().license_service


def get_vuln_db_service() -> VulnerabilityDatabaseService:
    """FastAPI dependency for vulnerability database"""
    return get_container().vuln_db_service


def get_scanner_service() -> SecurityScannerService:
    """FastAPI dependency for scanner"""
    return get_container().scanner_service


def get_integration_manager() -> IntegrationManager:
    """FastAPI dependency for integration manager"""
    return get_container().integration_manager


def get_soc_service() -> SOCCommandCenter:
    """FastAPI dependency for SOC service"""
    return get_container().soc_service


def get_hitl_service() -> HITLService:
    """FastAPI dependency for HITL service"""
    return get_container().hitl_service

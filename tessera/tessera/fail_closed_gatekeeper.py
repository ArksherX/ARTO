#!/usr/bin/env python3
"""
Fail-Closed Gatekeeper
If any critical component is unavailable, DENY all requests
Security over availability
"""

from typing import Optional, Tuple
from enum import Enum
from datetime import datetime
import time

class AccessDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    FAIL_CLOSED = "fail_closed"

class FailClosedGatekeeper:
    """
    Fail-Closed Security Architecture
    
    If ANY critical component is down:
    - Registry unreachable → DENY
    - Revocation list unreachable → DENY
    - Key management down → DENY
    - Database timeout → DENY
    
    This prioritizes security over availability
    """
    
    def __init__(self, persistence, kms, mtls_auth, abac_engine, anomaly_detector):
        self.persistence = persistence
        self.kms = kms
        self.mtls_auth = mtls_auth
        self.abac_engine = abac_engine
        self.anomaly_detector = anomaly_detector
        
        # Health check settings
        self.health_check_interval = 30  # seconds
        self.last_health_check = 0
        self.system_healthy = False
        
        # Circuit breaker
        self.circuit_open = False
        self.circuit_failures = 0
        self.circuit_failure_threshold = 5
    
    def validate_access(
        self,
        token: str,
        tool: str,
        resource_context: Optional[dict] = None,
        client_cert: Optional[str] = None
    ) -> Tuple[AccessDecision, str, Optional[dict]]:
        """
        Validate access with fail-closed guarantee
        
        Returns:
            (decision, reason, context)
        """
        resource_context = resource_context or {}
        
        # Step 0: System health check
        if not self._check_system_health():
            return (AccessDecision.FAIL_CLOSED, "System health check failed - failing closed for security", None)
        
        # Step 1: Circuit breaker check
        if self.circuit_open:
            return (
                AccessDecision.FAIL_CLOSED,
                "Circuit breaker open - too many recent failures",
                None
            )
        
        try:
            # Step 2: Token validation (requires KMS)
            try:
                payload = self.kms.verify_token(token)
                if not payload:
                    self._record_failure()
                    return (AccessDecision.DENY, "Invalid or expired token", None)
            except Exception as e:
                self._record_failure()
                return (
                    AccessDecision.FAIL_CLOSED,
                    f"Token validation failed: {e}",
                    None
                )
            
            agent_id = payload['sub']
            
            # Step 3: Revocation check (requires Redis)
            try:
                jti = payload.get('jti')
                if self.persistence.is_revoked(jti):
                    return (AccessDecision.DENY, "Token has been revoked", None)
            except Exception as e:
                self._record_failure()
                return (
                    AccessDecision.FAIL_CLOSED,
                    f"Revocation check failed: {e}",
                    None
                )
            
            # Step 4: mTLS certificate validation (if provided)
            if client_cert:
                try:
                    is_valid, cert_agent_id, fingerprint = \
                        self.mtls_auth.validate_client_certificate(client_cert)
                    
                    if not is_valid:
                        return (AccessDecision.DENY, fingerprint, None)  # fingerprint contains error
                    
                    if cert_agent_id != agent_id:
                        return (
                            AccessDecision.DENY,
                            "Agent ID mismatch between token and certificate",
                            None
                        )
                except Exception as e:
                    self._record_failure()
                    return (
                        AccessDecision.FAIL_CLOSED,
                        f"mTLS validation failed: {e}",
                        None
                    )
            
            # Step 5: Rate limiting check
            try:
                if not self.persistence.check_rate_limit(agent_id):
                    return (AccessDecision.DENY, "Rate limit exceeded", None)
            except Exception as e:
                self._record_failure()
                return (
                    AccessDecision.FAIL_CLOSED,
                    f"Rate limit check failed: {e}",
                    None
                )
            
            # Step 6: Agent registry check
            try:
                agent = self.persistence.get_agent(agent_id)
                if not agent:
                    return (AccessDecision.DENY, "Agent not found in registry", None)
                
                if agent['status'] != 'active':
                    return (
                        AccessDecision.DENY,
                        f"Agent status: {agent['status']}",
                        None
                    )
                
                if tool not in agent['allowed_tools']:
                    return (
                        AccessDecision.DENY,
                        f"Tool {tool} not in allowed_tools",
                        None
                    )
            except Exception as e:
                self._record_failure()
                return (
                    AccessDecision.FAIL_CLOSED,
                    f"Registry check failed: {e}",
                    None
                )
            
            # Step 7: ABAC policy evaluation
            try:
                abac_allowed, abac_reason = self.abac_engine.evaluate(
                    agent_id, tool, resource_context
                )
                if not abac_allowed:
                    return (AccessDecision.DENY, f"ABAC: {abac_reason}", None)
            except Exception as e:
                self._record_failure()
                return (
                    AccessDecision.FAIL_CLOSED,
                    f"ABAC evaluation failed: {e}",
                    None
                )
            
            # Step 8: Anomaly detection
            try:
                anomalies = self.anomaly_detector.check_for_anomalies(agent_id, tool)
                
                critical_anomalies = [a for a in anomalies if a.severity == 'critical']
                if critical_anomalies:
                    # Auto-suspend agent
                    self.persistence.update_agent_status(
                        agent_id,
                        'suspended',
                        f"Anomaly detected: {critical_anomalies[0].description}"
                    )
                    return (
                        AccessDecision.DENY,
                        f"Critical anomaly detected: {critical_anomalies[0].anomaly_type}",
                        {'anomaly': critical_anomalies[0]}
                    )
            except Exception as e:
                # Anomaly detection failure is not critical - log but allow
                print(f"⚠️  Anomaly detection failed: {e}")
            
            # All checks passed
            self._record_success()
            return (
                AccessDecision.ALLOW,
                "All security checks passed",
                {
                    'agent': agent,
                    'risk_threshold': payload.get('risk_threshold', 50)
                }
            )
            
        except Exception as e:
            # Unexpected error - fail closed
            self._record_failure()
            return (
                AccessDecision.FAIL_CLOSED,
                f"Unexpected error: {e}",
                None
            )
    
    def _check_system_health(self) -> bool:
        """
        Check if all critical systems are operational
        Cached for performance (checked every 30s)
        """
        now = time.time()
        
        if now - self.last_health_check < self.health_check_interval:
            return self.system_healthy
        
        try:
            # Check PostgreSQL
            conn = self.persistence.pg_pool.getconn()
            conn.cursor().execute('SELECT 1')
            self.persistence.pg_pool.putconn(conn)
            
            # Check Redis
            self.persistence.redis.ping()
            
            # System healthy
            self.system_healthy = True
            self.last_health_check = now
            return True
            
        except Exception as e:
            print(f"❌ Health check failed: {e}")
            self.system_healthy = False
            self.last_health_check = now
            return False
    
    def _record_failure(self):
        """Record failure for circuit breaker"""
        self.circuit_failures += 1
        
        if self.circuit_failures >= self.circuit_failure_threshold:
            self.circuit_open = True
            print(f"🚨 Circuit breaker OPEN - {self.circuit_failures} consecutive failures")
    
    def _record_success(self):
        """Record success - reset circuit breaker"""
        if self.circuit_failures > 0:
            self.circuit_failures = 0
        
        if self.circuit_open:
            self.circuit_open = False
            print("✅ Circuit breaker CLOSED - system recovering")

#!/usr/bin/env python3
"""
Production Persistence Layer
PostgreSQL for registry + Redis for revocation
"""

import os
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from redis import Redis
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json

class ProductionPersistence:
    """Thread-safe persistence using PostgreSQL + Redis"""
    
    def __init__(self):
        # PostgreSQL connection pool
        self.pg_pool = ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            dbname=os.getenv('POSTGRES_DB', 'tessera_iam'),
            user=os.getenv('POSTGRES_USER', 'tessera'),
            password=os.getenv('POSTGRES_PASSWORD', 'changeme'),
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            port=os.getenv('POSTGRES_PORT', '5432')
        )
        
        # Redis for fast lookups
        self.redis = Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            db=int(os.getenv('REDIS_DB', '0')),
            decode_responses=True
        )
        
        # Test connections
        self._test_connections()
    
    def _test_connections(self):
        """Verify database connections"""
        try:
            # Test PostgreSQL
            conn = self.pg_pool.getconn()
            conn.cursor().execute('SELECT 1')
            self.pg_pool.putconn(conn)
            
            # Test Redis
            self.redis.ping()
            
            print("✅ Database connections verified")
        except Exception as e:
            raise RuntimeError(f"Database connection failed: {e}")
    
    # ========================================================================
    # AGENT REGISTRY OPERATIONS (PostgreSQL)
    # ========================================================================
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Retrieve agent from PostgreSQL"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT agent_id, owner, status, allowed_tools, max_token_ttl, 
                       risk_threshold, status_reason, last_updated, mfa_enabled,
                       tenant_id,
                       certificate_fingerprint
                FROM agents WHERE agent_id = %s
            """, (agent_id,))
            
            row = cur.fetchone()
            if not row:
                return None
            
            return {
                'agent_id': row[0],
                'owner': row[1],
                'status': row[2],
                'allowed_tools': row[3],
                'max_token_ttl': row[4],
                'risk_threshold': row[5],
                'status_reason': row[6],
                'last_updated': row[7],
                'mfa_enabled': row[8],
                'tenant_id': row[9],
                'certificate_fingerprint': row[10]
            }
        finally:
            self.pg_pool.putconn(conn)
    
    def list_agents(self, status: Optional[str] = None, tenant_id: Optional[str] = None) -> List[Dict]:
        """List all agents"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            
            if status and tenant_id:
                cur.execute("""
                    SELECT agent_id, owner, status, allowed_tools, max_token_ttl, risk_threshold, tenant_id
                    FROM agents WHERE status = %s AND tenant_id = %s
                """, (status, tenant_id))
            elif status:
                cur.execute("""
                    SELECT agent_id, owner, status, allowed_tools, max_token_ttl, risk_threshold, tenant_id
                    FROM agents WHERE status = %s
                """, (status,))
            elif tenant_id:
                cur.execute("""
                    SELECT agent_id, owner, status, allowed_tools, max_token_ttl, risk_threshold, tenant_id
                    FROM agents WHERE tenant_id = %s
                """, (tenant_id,))
            else:
                cur.execute("""
                    SELECT agent_id, owner, status, allowed_tools, max_token_ttl, risk_threshold, tenant_id
                    FROM agents
                """)
            
            return [
                {
                    'agent_id': row[0],
                    'owner': row[1],
                    'status': row[2],
                    'allowed_tools': row[3],
                    'max_token_ttl': row[4],
                    'risk_threshold': row[5],
                    'tenant_id': row[6]
                }
                for row in cur.fetchall()
            ]
        finally:
            self.pg_pool.putconn(conn)
    
    def update_agent_status(self, agent_id: str, status: str, reason: str = None):
        """Update agent status"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                UPDATE agents 
                SET status = %s, status_reason = %s, last_updated = CURRENT_TIMESTAMP
                WHERE agent_id = %s
            """, (status, reason, agent_id))
            conn.commit()
        finally:
            self.pg_pool.putconn(conn)

    def create_agent(
        self,
        agent_id: str,
        owner: str,
        tenant_id: str,
        allowed_tools: List[str],
        max_token_ttl: int = 3600,
        risk_threshold: int = 50,
        status: str = "active"
    ):
        """Create a new agent in PostgreSQL."""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO agents (agent_id, owner, tenant_id, status, allowed_tools, max_token_ttl, risk_threshold, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (agent_id) DO UPDATE
                SET owner = EXCLUDED.owner,
                    tenant_id = EXCLUDED.tenant_id,
                    status = EXCLUDED.status,
                    allowed_tools = EXCLUDED.allowed_tools,
                    max_token_ttl = EXCLUDED.max_token_ttl,
                    risk_threshold = EXCLUDED.risk_threshold,
                    last_updated = CURRENT_TIMESTAMP
            """, (agent_id, owner, tenant_id, status, json.dumps(allowed_tools), max_token_ttl, risk_threshold))
            conn.commit()
        finally:
            self.pg_pool.putconn(conn)
    
    # ========================================================================
    # TOKEN REVOCATION (Redis - Sub-millisecond lookup)
    # ========================================================================
    
    def revoke_token(self, jti: str, reason: str = None, ttl: int = 3600):
        """Add token to Redis revocation list"""
        key = f"tessera:revoked:{jti}"
        self.redis.setex(key, ttl, json.dumps({
            'revoked_at': datetime.now().isoformat(),
            'reason': reason
        }))
        
        # Also log to PostgreSQL for audit
        self._log_token_revocation(jti, reason)
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked (Redis lookup)"""
        return self.redis.exists(f"tessera:revoked:{jti}") > 0
    
    def _log_token_revocation(self, jti: str, reason: str):
        """Log revocation to PostgreSQL"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                UPDATE token_metadata 
                SET revoked = TRUE, revocation_reason = %s
                WHERE jti = %s
            """, (reason, jti))
            conn.commit()
        finally:
            self.pg_pool.putconn(conn)
    
    # ========================================================================
    # AUDIT LOGGING (PostgreSQL + Streaming)
    # ========================================================================
    
    def log_audit(self, event_type: str, agent_id: str, details: str, 
                   status: str, severity: str = 'info', source_ip: str = None):
        """Log audit event to PostgreSQL"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO audit_log (timestamp, event_type, agent_id, details, status, severity, source_ip)
                VALUES (CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s)
            """, (event_type, agent_id, details, status, severity, source_ip))
            conn.commit()
            
            # Also stream to stdout (for SIEM ingestion)
            self._stream_to_siem({
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'agent_id': agent_id,
                'details': details,
                'status': status,
                'severity': severity,
                'source_ip': source_ip
            })
        finally:
            self.pg_pool.putconn(conn)
    
    def _stream_to_siem(self, event: Dict):
        """Stream to SIEM (structured JSON to stdout)"""
        print(json.dumps({
            '@timestamp': event['timestamp'],
            'service': 'tessera-iam',
            'log.level': event['severity'].upper(),
            'event.action': event['event_type'],
            'user.id': event['agent_id'],
            'message': event['details'],
            'event.outcome': event['status'],
            'source.ip': event['source_ip']
        }))
    
    # ========================================================================
    # RATE LIMITING
    # ========================================================================
    
    def check_rate_limit(self, agent_id: str, limit: int = 100, window_seconds: int = 60) -> bool:
        """
        Check if agent is within rate limit
        Returns: True if allowed, False if exceeded
        """
        key = f"tessera:ratelimit:{agent_id}"
        current = self.redis.get(key)
        
        if current is None:
            # First request in window
            self.redis.setex(key, window_seconds, 1)
            return True
        
        count = int(current)
        if count >= limit:
            return False
        
        self.redis.incr(key)
        return True
    
    # ========================================================================
    # BEHAVIORAL METRICS
    # ========================================================================
    
    def log_behavioral_metric(self, agent_id: str, tool: str, 
                              response_time_ms: int, success: bool):
        """Log behavioral data for anomaly detection"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO behavioral_metrics (agent_id, tool, timestamp, response_time_ms, success)
                VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s)
            """, (agent_id, tool, response_time_ms, success))
            conn.commit()
        finally:
            self.pg_pool.putconn(conn)
    
    def get_agent_baseline(self, agent_id: str, lookback_hours: int = 24) -> Dict:
        """Get behavioral baseline for anomaly detection"""
        conn = self.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    COUNT(*) as request_count,
                    AVG(response_time_ms) as avg_response_time,
                    STDDEV(response_time_ms) as stddev_response_time,
                    COUNT(*) FILTER (WHERE NOT success) as failure_count
                FROM behavioral_metrics
                WHERE agent_id = %s 
                  AND timestamp > NOW() - INTERVAL '%s hours'
            """, (agent_id, lookback_hours))
            
            row = cur.fetchone()
            return {
                'request_count': row[0] or 0,
                'avg_response_time': float(row[1]) if row[1] else 0,
                'stddev_response_time': float(row[2]) if row[2] else 0,
                'failure_count': row[3] or 0
            }
        finally:
            self.pg_pool.putconn(conn)

# Singleton instance
_persistence = None

def get_persistence() -> ProductionPersistence:
    """Get or create persistence instance"""
    global _persistence
    if _persistence is None:
        _persistence = ProductionPersistence()
    return _persistence

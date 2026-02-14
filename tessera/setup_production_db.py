#!/usr/bin/env python3
"""
Production Database Setup
Migrates from JSON to Redis (revocation) + PostgreSQL (registry)
"""

import os
import psycopg2
from redis import Redis
import json

# Database schemas
POSTGRES_SCHEMA = """
-- Agent Registry Table
CREATE TABLE IF NOT EXISTS agents (
    agent_id VARCHAR(255) PRIMARY KEY,
    owner VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) DEFAULT 'default',
    status VARCHAR(50) DEFAULT 'active',
    allowed_tools TEXT[] NOT NULL,
    max_token_ttl INTEGER DEFAULT 300,
    risk_threshold INTEGER DEFAULT 50,
    status_reason TEXT,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    certificate_fingerprint VARCHAR(255),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'blacklisted'))
);

-- Audit Log Table (for persistence)
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    agent_id VARCHAR(255),
    details TEXT,
    status VARCHAR(50),
    severity VARCHAR(20) DEFAULT 'info',
    source_ip VARCHAR(45),
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE SET NULL
);

-- Token Metadata Table (not the tokens themselves, just tracking)
CREATE TABLE IF NOT EXISTS token_metadata (
    jti VARCHAR(255) PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    tool VARCHAR(100) NOT NULL,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    risk_threshold INTEGER,
    revoked BOOLEAN DEFAULT FALSE,
    revocation_reason TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

-- Behavioral Analytics Table
CREATE TABLE IF NOT EXISTS behavioral_metrics (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    tool VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    response_time_ms INTEGER,
    success BOOLEAN,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

-- Rate Limiting Table
CREATE TABLE IF NOT EXISTS rate_limits (
    agent_id VARCHAR(255) PRIMARY KEY,
    requests_count INTEGER DEFAULT 0,
    window_start TIMESTAMP NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_tokens_agent ON token_metadata(agent_id);
CREATE INDEX IF NOT EXISTS idx_behavioral_agent ON behavioral_metrics(agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);
"""

ALTER_TENANT = """
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255) DEFAULT 'default';
"""

def setup_postgres():
    """Initialize PostgreSQL database"""
    print("🔧 Setting up PostgreSQL...")
    
    # Connection details from environment
    conn_params = {
        'dbname': os.getenv('POSTGRES_DB', 'tessera_iam'),
        'user': os.getenv('POSTGRES_USER', 'tessera'),
        'password': os.getenv('POSTGRES_PASSWORD', 'changeme'),
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'port': os.getenv('POSTGRES_PORT', '5432')
    }
    
    try:
        conn = psycopg2.connect(**conn_params)
        cur = conn.cursor()
        
        # Execute schema
        cur.execute(POSTGRES_SCHEMA)
        cur.execute(ALTER_TENANT)
        conn.commit()
        
        print("✅ PostgreSQL schema created")
        
        # Migrate existing JSON data
        migrate_json_to_postgres(cur, conn)
        
        cur.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ PostgreSQL setup failed: {e}")
        return False

def migrate_json_to_postgres(cur, conn):
    """Migrate existing JSON registry to PostgreSQL"""
    json_file = 'data/tessera_registry.json'
    
    if not os.path.exists(json_file):
        print("⚠️  No existing registry to migrate")
        return
    
    with open(json_file, 'r') as f:
        registry = json.load(f)
    
    for agent_id, config in registry.items():
        cur.execute("""
            INSERT INTO agents (agent_id, owner, tenant_id, status, allowed_tools, max_token_ttl, risk_threshold)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id) DO NOTHING
        """, (
            agent_id,
            config['owner'],
            config.get('tenant_id', 'default'),
            config.get('status', 'active'),
            config['allowed_tools'],
            config.get('max_token_ttl', 300),
            config.get('risk_threshold', 50)
        ))
    
    conn.commit()
    print(f"✅ Migrated {len(registry)} agents to PostgreSQL")

def setup_redis():
    """Initialize Redis connection"""
    print("🔧 Setting up Redis...")
    
    try:
        redis_client = Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', '6379')),
            db=int(os.getenv('REDIS_DB', '0')),
            decode_responses=True
        )
        
        # Test connection
        redis_client.ping()
        print("✅ Redis connected")
        
        # Set up Redis key namespaces
        redis_client.set('tessera:system:version', '1.0.0')
        
        return True
        
    except Exception as e:
        print(f"❌ Redis setup failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  TESSERA IAM - PRODUCTION DATABASE SETUP")
    print("=" * 70)
    
    postgres_ok = setup_postgres()
    redis_ok = setup_redis()
    
    if postgres_ok and redis_ok:
        print("\n✅ Production databases ready!")
    else:
        print("\n❌ Setup incomplete. Check errors above.")

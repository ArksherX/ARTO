-- Phase 6: Multi-tenant SaaS core

ALTER TABLE IF EXISTS vestigia_events
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_vestigia_tenant_id
    ON vestigia_events (tenant_id);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id       VARCHAR(255) PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    plan            VARCHAR(50)  DEFAULT 'free',
    status          VARCHAR(50)  DEFAULT 'active',
    created_at      TIMESTAMPTZ  DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_users (
    user_id         VARCHAR(255) PRIMARY KEY,
    tenant_id       VARCHAR(255) REFERENCES tenants(tenant_id),
    email           VARCHAR(255) NOT NULL,
    role            VARCHAR(50)  DEFAULT 'viewer',
    status          VARCHAR(50)  DEFAULT 'active',
    created_at      TIMESTAMPTZ  DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id          VARCHAR(255) PRIMARY KEY,
    tenant_id       VARCHAR(255) REFERENCES tenants(tenant_id),
    user_id         VARCHAR(255) REFERENCES tenant_users(user_id),
    label           VARCHAR(255) DEFAULT 'default',
    key_hash        VARCHAR(64)  NOT NULL,
    status          VARCHAR(50)  DEFAULT 'active',
    created_at      TIMESTAMPTZ  DEFAULT now(),
    last_used       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS tenant_usage (
    tenant_id       VARCHAR(255) REFERENCES tenants(tenant_id),
    day             DATE NOT NULL,
    events_count    INTEGER DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);

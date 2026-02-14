-- Phase 5 migrations: anomaly baselines + feedback

BEGIN;

CREATE TABLE IF NOT EXISTS anomaly_baselines (
    actor_id            VARCHAR(255) PRIMARY KEY,
    avg_events_per_hour DOUBLE PRECISION DEFAULT 0,
    avg_payload_size    DOUBLE PRECISION DEFAULT 0,
    hour_bucket_start   TIMESTAMPTZ,
    hour_count          INTEGER DEFAULT 0,
    tools               JSONB DEFAULT '{}'::jsonb,
    last_seen           TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS anomaly_feedback (
    feedback_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            VARCHAR(255),
    actor_id            VARCHAR(255),
    label               VARCHAR(50) DEFAULT 'benign',
    note                TEXT,
    created_at          TIMESTAMPTZ DEFAULT now()
);

-- Risk history for forecasting
CREATE TABLE IF NOT EXISTS risk_history (
    risk_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id            VARCHAR(255) NOT NULL,
    event_id            VARCHAR(255),
    risk_score          DOUBLE PRECISION NOT NULL,
    signals             JSONB DEFAULT '[]'::jsonb,
    recorded_at         TIMESTAMPTZ DEFAULT now()
);

-- Playbook execution ledger
CREATE TABLE IF NOT EXISTS playbook_executions (
    execution_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_name       VARCHAR(255) NOT NULL,
    actor_id            VARCHAR(255),
    trigger_reason      TEXT,
    status              VARCHAR(50) DEFAULT 'executed',
    details             JSONB DEFAULT '{}'::jsonb,
    executed_at         TIMESTAMPTZ DEFAULT now()
);

COMMIT;

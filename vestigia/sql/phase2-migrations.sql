-- =============================================================================
-- Vestigia Phase 2 Migrations
-- Adds data-classification, PII-scrubbing, cost governance, SIEM forwarding,
-- and dead-letter queue capabilities.
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. New columns on vestigia_events
-- ---------------------------------------------------------------------------
ALTER TABLE vestigia_events
    ADD COLUMN IF NOT EXISTS data_classification VARCHAR(20) DEFAULT 'INTERNAL',
    ADD COLUMN IF NOT EXISTS pii_scrubbed        BOOLEAN     DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS sampling_decision    VARCHAR(20),
    ADD COLUMN IF NOT EXISTS cost_weight          DECIMAL(5,2) DEFAULT 1.0;

COMMENT ON COLUMN vestigia_events.data_classification IS
    'Data sensitivity label: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED.';
COMMENT ON COLUMN vestigia_events.pii_scrubbed IS
    'TRUE when personally-identifiable information has been redacted from evidence.';
COMMENT ON COLUMN vestigia_events.sampling_decision IS
    'Sampling outcome: SAMPLED, NOT_SAMPLED, FORCE_KEEP. NULL means pre-Phase-2 row.';
COMMENT ON COLUMN vestigia_events.cost_weight IS
    'Relative cost multiplier for budget tracking (1.0 = baseline).';

-- ---------------------------------------------------------------------------
-- 2. SIEM forward queue
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem_forward_queue (
    queue_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID            NOT NULL REFERENCES vestigia_events(event_id),
    target          VARCHAR(100)    NOT NULL,
    status          VARCHAR(20)     DEFAULT 'pending',
    retry_count     INTEGER         DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ     DEFAULT now(),
    forwarded_at    TIMESTAMPTZ
);

COMMENT ON TABLE siem_forward_queue IS
    'Outbound queue for forwarding audit events to external SIEM systems '
    '(e.g. Splunk, Sentinel, Elastic). Rows move from pending -> forwarded '
    'or pending -> failed -> dead_letter_queue.';

CREATE INDEX IF NOT EXISTS idx_siem_queue_status
    ON siem_forward_queue (status);

CREATE INDEX IF NOT EXISTS idx_siem_queue_event_id
    ON siem_forward_queue (event_id);

CREATE INDEX IF NOT EXISTS idx_siem_queue_created_at
    ON siem_forward_queue (created_at);

-- ---------------------------------------------------------------------------
-- 3. Dead-letter queue for failed SIEM forwards
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    dlq_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id        UUID            NOT NULL REFERENCES siem_forward_queue(queue_id),
    event_id        UUID            NOT NULL REFERENCES vestigia_events(event_id),
    target          VARCHAR(100)    NOT NULL,
    failure_reason  TEXT,
    retry_count     INTEGER         DEFAULT 0,
    last_error      TEXT,
    original_payload JSONB,
    created_at      TIMESTAMPTZ     DEFAULT now(),
    expires_at      TIMESTAMPTZ     DEFAULT (now() + INTERVAL '30 days')
);

COMMENT ON TABLE dead_letter_queue IS
    'Permanently-failed SIEM forward attempts. Rows land here after the '
    'siem_forward_queue exhausts its retry budget. Retained for 30 days '
    'by default for manual investigation and replay.';

CREATE INDEX IF NOT EXISTS idx_dlq_event_id
    ON dead_letter_queue (event_id);

CREATE INDEX IF NOT EXISTS idx_dlq_created_at
    ON dead_letter_queue (created_at);

CREATE INDEX IF NOT EXISTS idx_dlq_expires_at
    ON dead_letter_queue (expires_at);

-- ---------------------------------------------------------------------------
-- 4. Cost budgets
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cost_budgets (
    budget_id       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    period          VARCHAR(20)     NOT NULL,
    budget_limit    DECIMAL(10,2)   NOT NULL,
    current_spend   DECIMAL(10,2)   DEFAULT 0,
    alert_threshold DECIMAL(5,2)    DEFAULT 0.8
);

COMMENT ON TABLE cost_budgets IS
    'Per-period budget envelopes for audit-event ingestion costs. '
    'alert_threshold is expressed as a fraction (0.0-1.0) of budget_limit; '
    'when current_spend / budget_limit >= alert_threshold an alert fires.';

CREATE INDEX IF NOT EXISTS idx_cost_budgets_period
    ON cost_budgets (period);

COMMIT;

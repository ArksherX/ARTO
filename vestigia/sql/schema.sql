-- =============================================================================
-- Vestigia Production PostgreSQL Schema
-- Immutable audit ledger with hash-chain integrity, append-only enforcement,
-- witness anchoring, and meta-audit access logging.
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Core event ledger table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vestigia_events (
    event_id        UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    tenant_id       VARCHAR(255),
    actor_id        VARCHAR(255)    NOT NULL,
    action_type     VARCHAR(100)    NOT NULL,
    status          VARCHAR(50)     NOT NULL,
    severity        VARCHAR(20)     DEFAULT 'INFO',
    evidence        JSONB           NOT NULL,
    integrity_hash  VARCHAR(64)     NOT NULL,
    previous_hash   VARCHAR(64)     NOT NULL,
    event_sequence  BIGSERIAL,
    trace_id        VARCHAR(64),
    span_id         VARCHAR(64),
    metadata        JSONB           DEFAULT '{}'
);

COMMENT ON TABLE vestigia_events IS
    'Immutable append-only audit ledger. Each row is hash-chained to the '
    'previous entry to guarantee tamper-evidence. UPDATE and DELETE are '
    'blocked by the prevent_vestigia_mutation trigger.';

-- ---------------------------------------------------------------------------
-- 2. Witness anchor table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS witness_anchors (
    anchor_id       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ     DEFAULT now(),
    merkle_root     VARCHAR(64),
    entry_count     INTEGER,
    anchor_hash     VARCHAR(64),
    anchor_type     VARCHAR(50)     DEFAULT 'merkle',
    external_ref    TEXT
);

COMMENT ON TABLE witness_anchors IS
    'Periodic Merkle-root snapshots of the event ledger used for '
    'out-of-band integrity verification and external anchoring.';

-- ---------------------------------------------------------------------------
-- 3. Meta-audit access log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_log (
    access_id       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ     DEFAULT now(),
    user_id         VARCHAR(255),
    query_text      TEXT,
    rows_accessed   INTEGER,
    ip_address      INET,
    user_agent      TEXT,
    alert_triggered BOOLEAN         DEFAULT FALSE
);

COMMENT ON TABLE access_log IS
    'Meta-audit trail that records every query executed against the '
    'vestigia_events table. Used for compliance reporting and anomaly '
    'detection on ledger access patterns.';

-- ---------------------------------------------------------------------------
-- 3b. Blockchain anchors
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blockchain_anchors (
    anchor_id       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ     DEFAULT now(),
    merkle_root     VARCHAR(64)     NOT NULL,
    batch_size      INTEGER         NOT NULL,
    provider        VARCHAR(50)     NOT NULL,
    external_ref    TEXT
);

COMMENT ON TABLE blockchain_anchors IS
    'External blockchain anchoring records for merkle roots.';

-- ---------------------------------------------------------------------------
-- 7. Anomaly baselines + feedback (Phase 5)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- 8. Risk history + playbook executions (Phase 5)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_history (
    risk_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id            VARCHAR(255) NOT NULL,
    event_id            VARCHAR(255),
    risk_score          DOUBLE PRECISION NOT NULL,
    signals             JSONB DEFAULT '[]'::jsonb,
    recorded_at         TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    execution_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_name       VARCHAR(255) NOT NULL,
    actor_id            VARCHAR(255),
    trigger_reason      TEXT,
    status              VARCHAR(50) DEFAULT 'executed',
    details             JSONB DEFAULT '{}'::jsonb,
    executed_at         TIMESTAMPTZ DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 9. Multi-tenant SaaS core (Phase 6)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- 4. Indexes for high-performance querying
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_vestigia_timestamp
    ON vestigia_events (timestamp);

CREATE INDEX IF NOT EXISTS idx_vestigia_actor_id
    ON vestigia_events (actor_id);

CREATE INDEX IF NOT EXISTS idx_vestigia_tenant_id
    ON vestigia_events (tenant_id);

CREATE INDEX IF NOT EXISTS idx_vestigia_action_type
    ON vestigia_events (action_type);

CREATE INDEX IF NOT EXISTS idx_vestigia_status
    ON vestigia_events (status);

CREATE INDEX IF NOT EXISTS idx_vestigia_trace_id
    ON vestigia_events (trace_id);

CREATE INDEX IF NOT EXISTS idx_vestigia_integrity_hash
    ON vestigia_events (integrity_hash);

CREATE INDEX IF NOT EXISTS idx_vestigia_event_sequence
    ON vestigia_events (event_sequence);

-- ---------------------------------------------------------------------------
-- 5. Append-only trigger: prevent UPDATE and DELETE on vestigia_events
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_prevent_vestigia_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION
            'vestigia_events is append-only: UPDATE operations are forbidden. '
            'event_id=%, actor_id=%',
            OLD.event_id, OLD.actor_id
        USING ERRCODE = 'restrict_violation';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'vestigia_events is append-only: DELETE operations are forbidden. '
            'event_id=%, actor_id=%',
            OLD.event_id, OLD.actor_id
        USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NULL;  -- never reached
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_vestigia_mutation ON vestigia_events;

CREATE TRIGGER prevent_vestigia_mutation
    BEFORE UPDATE OR DELETE ON vestigia_events
    FOR EACH ROW
    EXECUTE FUNCTION fn_prevent_vestigia_mutation();

-- ---------------------------------------------------------------------------
-- 6. Hash-chain integrity validation function
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_validate_hash_chain(
    p_limit  INTEGER DEFAULT NULL
)
RETURNS TABLE (
    is_valid        BOOLEAN,
    break_sequence  BIGINT,
    break_event_id  UUID,
    details         TEXT
) AS $$
DECLARE
    rec             RECORD;
    prev_hash       VARCHAR(64);
    row_count       INTEGER := 0;
    checked         INTEGER := 0;
BEGIN
    -- Walk the chain in sequence order
    FOR rec IN
        SELECT e.event_id,
               e.event_sequence,
               e.integrity_hash,
               e.previous_hash
        FROM   vestigia_events e
        ORDER  BY e.event_sequence ASC
    LOOP
        row_count := row_count + 1;

        -- The first row (genesis) has no predecessor to validate against,
        -- so we just record its hash and move on.
        IF row_count = 1 THEN
            prev_hash := rec.integrity_hash;
            CONTINUE;
        END IF;

        -- Every subsequent row must reference the previous row's hash.
        IF rec.previous_hash IS DISTINCT FROM prev_hash THEN
            is_valid       := FALSE;
            break_sequence := rec.event_sequence;
            break_event_id := rec.event_id;
            details        := format(
                'Chain break at sequence %s (event %s): '
                'expected previous_hash=%s but found=%s',
                rec.event_sequence, rec.event_id,
                prev_hash, rec.previous_hash
            );
            RETURN NEXT;
            RETURN;
        END IF;

        prev_hash := rec.integrity_hash;
        checked   := checked + 1;

        IF p_limit IS NOT NULL AND checked >= p_limit THEN
            EXIT;
        END IF;
    END LOOP;

    -- If we reach here the chain is intact.
    is_valid       := TRUE;
    break_sequence := NULL;
    break_event_id := NULL;
    details        := format('Hash chain valid: %s links verified.', checked);
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION fn_validate_hash_chain IS
    'Walks vestigia_events in event_sequence order and verifies that every '
    'row''s previous_hash matches the integrity_hash of its predecessor. '
    'Returns a single row indicating validity or the first break point.';

COMMIT;

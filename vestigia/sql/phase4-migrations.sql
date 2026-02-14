-- Phase 4 migrations: blockchain anchors + access log enhancements

BEGIN;

CREATE TABLE IF NOT EXISTS blockchain_anchors (
    anchor_id       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ     DEFAULT now(),
    merkle_root     VARCHAR(64)     NOT NULL,
    batch_size      INTEGER         NOT NULL,
    provider        VARCHAR(50)     NOT NULL,
    external_ref    TEXT
);

ALTER TABLE access_log
    ADD COLUMN IF NOT EXISTS user_agent TEXT;

COMMIT;

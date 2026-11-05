-- =============================================================================
-- Phase 7: make concurrent appends safe
--
-- The ledger is about to run on Cloud Run, where several instances append at
-- once. The existing append took the latest row with SELECT ... FOR UPDATE,
-- which is not enough: under READ COMMITTED a statement that blocks on the lock
-- does not then see a row the other transaction INSERTED, so two appends can
-- read the same parent and fork the chain. Each fork verifies as internally
-- valid, so nothing would surface the problem.
--
-- Two independent guards, because this is the product's core claim:
--   1. an advisory lock in append_event serialises writers (in postgres_ledger.py)
--   2. this constraint makes a fork impossible to commit even if guard 1 is
--      bypassed, misconfigured, or a future caller forgets it
-- =============================================================================

BEGIN;

-- Each hash may be the parent of exactly one entry. A second append chaining
-- off the same parent violates this and fails loudly instead of forking.
ALTER TABLE vestigia_events
    DROP CONSTRAINT IF EXISTS vestigia_events_previous_hash_unique;

ALTER TABLE vestigia_events
    ADD CONSTRAINT vestigia_events_previous_hash_unique UNIQUE (previous_hash);

COMMENT ON CONSTRAINT vestigia_events_previous_hash_unique ON vestigia_events IS
    'A hash can have exactly one successor. Blocks a forked chain from ever '
    'committing, including under concurrent writers on separate instances.';

-- Verification walks the chain in sequence order on every integrity check.
CREATE INDEX IF NOT EXISTS idx_vestigia_events_sequence
    ON vestigia_events (event_sequence);

COMMIT;

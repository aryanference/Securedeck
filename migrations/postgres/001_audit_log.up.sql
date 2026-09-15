CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    source_service  TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    agent_id        TEXT,
    action          TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    detail          JSONB,
    entry_hash      BYTEA NOT NULL,
    prev_hash       BYTEA NOT NULL,
    sequence_number BIGINT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- THE critical constraint: append-only at the DATABASE level (SEC-06)
CREATE OR REPLACE FUNCTION reject_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();

-- Performance indexes
CREATE INDEX idx_audit_agent ON audit_log(agent_id, created_at);
CREATE INDEX idx_audit_type ON audit_log(event_type, created_at);
CREATE INDEX idx_audit_sequence ON audit_log(sequence_number);

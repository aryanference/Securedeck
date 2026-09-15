CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE,
    source_service  TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    agent_id        TEXT,
    action          TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    detail          TEXT,
    entry_hash      BLOB NOT NULL,
    prev_hash       BLOB NOT NULL,
    sequence_number INTEGER NOT NULL UNIQUE,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- THE critical constraint: append-only at the DATABASE level (SEC-06)
CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log records cannot be modified or deleted');
END;

CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log records cannot be modified or deleted');
END;

-- Performance indexes
CREATE INDEX idx_audit_agent ON audit_log(agent_id, created_at);
CREATE INDEX idx_audit_type ON audit_log(event_type, created_at);
CREATE INDEX idx_audit_sequence ON audit_log(sequence_number);

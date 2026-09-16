CREATE TABLE agent_task_descriptions (
    agent_id    TEXT PRIMARY KEY REFERENCES agents(id),
    description TEXT NOT NULL,
    categories  TEXT NOT NULL,
    keywords    TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by  TEXT NOT NULL
);

CREATE TABLE drift_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    condition   TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    enabled     INTEGER NOT NULL DEFAULT 1
);

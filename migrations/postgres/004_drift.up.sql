CREATE TABLE agent_task_descriptions (
    agent_id    UUID PRIMARY KEY REFERENCES agents(id),
    description TEXT NOT NULL,
    categories  TEXT[] NOT NULL,
    keywords    TEXT[] NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  TEXT NOT NULL
);

CREATE TABLE drift_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    condition   JSONB NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    enabled     BOOLEAN NOT NULL DEFAULT TRUE
);

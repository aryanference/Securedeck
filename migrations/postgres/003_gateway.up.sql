CREATE TABLE policies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    description  TEXT,
    rules        JSONB NOT NULL,           -- Array of rule objects
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL
);

CREATE TABLE agent_policies (
    agent_id    UUID NOT NULL REFERENCES agents(id),
    policy_id   UUID NOT NULL REFERENCES policies(id),
    PRIMARY KEY (agent_id, policy_id)
);

CREATE TABLE egress_allowlist (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope       TEXT NOT NULL,              -- "global" or agent_id
    domain      TEXT NOT NULL,
    port        INTEGER,
    protocol    TEXT DEFAULT 'https',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  TEXT NOT NULL,
    UNIQUE(scope, domain, port, protocol)
);

CREATE INDEX idx_egress_scope ON egress_allowlist(scope);
CREATE INDEX idx_agent_policies_agent ON agent_policies(agent_id);

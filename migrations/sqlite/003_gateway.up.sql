CREATE TABLE policies (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT,
    rules        TEXT NOT NULL,             -- JSON array of rule objects
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by   TEXT NOT NULL
);

CREATE TABLE agent_policies (
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    policy_id   TEXT NOT NULL REFERENCES policies(id),
    PRIMARY KEY (agent_id, policy_id)
);

CREATE TABLE egress_allowlist (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,              -- "global" or agent_id
    domain      TEXT NOT NULL,
    port        INTEGER,
    protocol    TEXT DEFAULT 'https',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  TEXT NOT NULL,
    UNIQUE(scope, domain, port, protocol)
);

CREATE INDEX idx_egress_scope ON egress_allowlist(scope);
CREATE INDEX idx_agent_policies_agent ON agent_policies(agent_id);

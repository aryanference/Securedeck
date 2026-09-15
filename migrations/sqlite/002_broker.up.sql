CREATE TABLE agents (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    org_id      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'terminated')),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agent_scopes (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    scope       TEXT NOT NULL,               
    granted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by  TEXT NOT NULL,               
    UNIQUE(agent_id, scope)
);

CREATE TABLE token_issuance_log (
    id          TEXT PRIMARY KEY,
    token_id    TEXT NOT NULL UNIQUE,         
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    scopes      TEXT NOT NULL, -- Stored as JSON array or comma separated in sqlite
    issued_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT 0,
    revoked_at  DATETIME,
    revoked_by  TEXT                          
);

CREATE INDEX idx_token_active ON token_issuance_log(token_id) WHERE revoked = 0;
CREATE INDEX idx_token_agent ON token_issuance_log(agent_id, issued_at);

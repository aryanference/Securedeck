CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT,
    org_id      UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'terminated')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_scopes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id),
    scope       TEXT NOT NULL,               -- e.g. "read:files", "execute:code"
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  TEXT NOT NULL,               -- operator ID
    UNIQUE(agent_id, scope)
);

CREATE TABLE token_issuance_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id    TEXT NOT NULL UNIQUE,         -- JTI from the PASETO
    agent_id    UUID NOT NULL REFERENCES agents(id),
    scopes      TEXT[] NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at  TIMESTAMPTZ,
    revoked_by  TEXT                          -- "operator:<id>", "killswitch", "expiry"
);

-- Index for fast revocation checks
CREATE INDEX idx_token_active ON token_issuance_log(token_id) WHERE revoked = FALSE;
CREATE INDEX idx_token_agent ON token_issuance_log(agent_id, issued_at);

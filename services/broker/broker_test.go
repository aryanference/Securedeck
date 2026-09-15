package broker

import (
	"context"
	"testing"
	"time"

	broker "github.com/aryanference/securedeck/gen/go/broker/v1"
	"github.com/aryanference/securedeck/internal/crypto"
	"github.com/aryanference/securedeck/internal/db"
)

func TestBrokerServer_RegisterAndIssue(t *testing.T) {
	database, err := db.NewSQLiteDB("file::memory:?cache=shared&_mutex=full")
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer database.Close()

	ctx := context.Background()
	_, err = database.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			org_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active'
		);
		CREATE TABLE IF NOT EXISTS agent_scopes (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES agents(id),
			scope TEXT NOT NULL,
			granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			granted_by TEXT NOT NULL,
			UNIQUE(agent_id, scope)
		);
		CREATE TABLE IF NOT EXISTS token_issuance_log (
			id TEXT PRIMARY KEY,
			token_id TEXT NOT NULL UNIQUE,
			agent_id TEXT NOT NULL REFERENCES agents(id),
			scopes TEXT NOT NULL,
			issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at DATETIME,
			revoked_by TEXT
		);
	`)
	if err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	priv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	revCache := NewRevocationCache(database, 1*time.Second)
	s := NewServer(database, priv, revCache)

	// Register agent
	regResp, err := s.RegisterAgent(ctx, &broker.RegisterAgentRequest{
		Name:          "test-agent",
		Description:   "a test agent",
		OrgId:         "org-1",
		InitialScopes: []string{"read:files", "execute:code"},
	})
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}
	if regResp.AgentId == "" {
		t.Error("expected non-empty agent_id")
	}

	// Issue token
	issueResp, err := s.IssueToken(ctx, &broker.IssueTokenRequest{
		AgentId:         regResp.AgentId,
		RequestedScopes: []string{"read:files"},
	})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if issueResp.Token == "" {
		t.Error("expected non-empty token")
	}

	// Validate token
	validateResp, err := s.ValidateToken(ctx, &broker.ValidateTokenRequest{
		Token: issueResp.Token,
	})
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if !validateResp.IsValid {
		t.Error("expected token to be valid")
	}
	if validateResp.AgentId != regResp.AgentId {
		t.Errorf("expected agent_id %s, got %s", regResp.AgentId, validateResp.AgentId)
	}
}

package auditlog

import (
	"context"
	"testing"

	audit "github.com/aryanference/securedeck/gen/go/audit/v1"
	"github.com/aryanference/securedeck/internal/db"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Compile-time check: audit and timestamppb must be used
var _ = timestamppb.Now
var _ *audit.AuditEvent

func TestServer_LogEvent(t *testing.T) {
	database, err := db.NewSQLiteDB("file::memory:?cache=shared&_mutex=full")
	if err != nil {
		t.Fatalf("failed to create memory db: %v", err)
	}
	defer database.Close()

	ctx := context.Background()
	_, err = database.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS audit_log (
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
		)
	`)
	if err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	s := NewServer(database, nil)

	resp, err := s.LogEvent(ctx, &audit.LogEventRequest{
		SourceService: "test",
		EventType:     "test.event",
		AgentId:       "agent-1",
		Action:        "read",
		Outcome:       "allowed",
	})
	if err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}
	if resp.EventId == "" {
		t.Error("expected non-empty event_id")
	}
	if resp.SequenceNumber != 0 {
		t.Errorf("expected sequence 0, got %d", resp.SequenceNumber)
	}

	// Log a second event and verify sequence increments
	resp2, err := s.LogEvent(ctx, &audit.LogEventRequest{
		SourceService: "test",
		EventType:     "test.event",
		AgentId:       "agent-1",
		Action:        "write",
		Outcome:       "denied",
	})
	if err != nil {
		t.Fatalf("second LogEvent failed: %v", err)
	}
	if resp2.SequenceNumber != 1 {
		t.Errorf("expected sequence 1, got %d", resp2.SequenceNumber)
	}

	// Verify hash chain
	chainResp, err := s.VerifyChain(ctx, &audit.VerifyChainRequest{})
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !chainResp.IsValid {
		t.Errorf("expected valid chain, got broken at %d", chainResp.BrokenAtSequence)
	}
}

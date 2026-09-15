package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	audit "github.com/aryanference/securedeck/gen/go/audit/v1"
	"github.com/aryanference/securedeck/internal/crypto"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	audit.UnimplementedAuditLogServiceServer
	db        db.DB
	publisher *Publisher
	mu        sync.Mutex // Serialize writes to maintain hash chain integrity
}

func NewServer(database db.DB, publisher *Publisher) *Server {
	return &Server{
		db:        database,
		publisher: publisher,
	}
}

func (s *Server) LogEvent(ctx context.Context, req *audit.LogEventRequest) (*audit.LogEventResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to begin tx: %v", err)
	}
	defer tx.Rollback()

	var prevHash []byte
	var seq uint64
	err = tx.QueryRowContext(ctx,
		"SELECT entry_hash, sequence_number FROM audit_log ORDER BY sequence_number DESC LIMIT 1",
	).Scan(&prevHash, &seq)
	if err != nil {
		// Genesis block
		prevHash = make([]byte, 32)
		seq = 0
	} else {
		seq++
	}

	eventID := uuid.New().String()
	eventTime := time.Now()
	if req.Timestamp != nil {
		eventTime = req.Timestamp.AsTime()
	}

	eventData := map[string]any{
		"event_id":        eventID,
		"source_service":  req.SourceService,
		"event_type":      req.EventType,
		"agent_id":        req.AgentId,
		"action":          req.Action,
		"outcome":         req.Outcome,
		"sequence_number": seq,
	}
	content, _ := json.Marshal(eventData)
	entryHash := crypto.ComputeEntryHash(prevHash, content)

	// Use ? placeholders — compatible with both modernc.org/sqlite and pgx stdlib driver
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log
			(event_id, source_service, event_type, agent_id, action, outcome, detail, entry_hash, prev_hash, sequence_number, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID, req.SourceService, req.EventType, req.AgentId, req.Action, req.Outcome,
		req.Detail, entryHash, prevHash, seq, eventTime,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to insert audit log: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit tx: %v", err)
	}

	auditEvent := &audit.AuditEvent{
		EventId:        eventID,
		SourceService:  req.SourceService,
		EventType:      req.EventType,
		AgentId:        req.AgentId,
		Action:         req.Action,
		Outcome:        req.Outcome,
		Detail:         req.Detail,
		Timestamp:      timestamppb.New(eventTime),
		EntryHash:      entryHash,
		PrevHash:       prevHash,
		SequenceNumber: seq,
	}

	if s.publisher != nil {
		if err := s.publisher.PublishEvent(auditEvent); err != nil {
			fmt.Printf("Warning: failed to publish to NATS: %v\n", err)
		}
	}

	return &audit.LogEventResponse{
		EventId:        eventID,
		EntryHash:      entryHash,
		SequenceNumber: seq,
	}, nil
}

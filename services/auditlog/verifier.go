package auditlog

import (
	"context"
	"encoding/json"

	audit "github.com/aryanference/securedeck/gen/go/audit/v1"
	"github.com/aryanference/securedeck/internal/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) VerifyChain(ctx context.Context, req *audit.VerifyChainRequest) (*audit.VerifyChainResponse, error) {
	query := "SELECT entry_hash, prev_hash, event_id, source_service, event_type, agent_id, action, outcome, sequence_number FROM audit_log"
	var args []any

	if req.FromSequence > 0 && req.ToSequence > 0 {
		query += " WHERE sequence_number >= ? AND sequence_number <= ?"
		args = append(args, req.FromSequence, req.ToSequence)
	} else if req.FromSequence > 0 {
		query += " WHERE sequence_number >= ?"
		args = append(args, req.FromSequence)
	} else if req.ToSequence > 0 {
		query += " WHERE sequence_number <= ?"
		args = append(args, req.ToSequence)
	}
	query += " ORDER BY sequence_number ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query audit log: %v", err)
	}
	defer rows.Close()

	var entries []crypto.AuditEntry
	var sequences []uint64

	for rows.Next() {
		var entryHash, prevHash []byte
		var eventID, sourceService, eventType, agentID, action, outcome string
		var seq uint64

		err := rows.Scan(&entryHash, &prevHash, &eventID, &sourceService, &eventType, &agentID, &action, &outcome, &seq)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to scan row: %v", err)
		}

		eventData := map[string]any{
			"event_id":        eventID,
			"source_service":  sourceService,
			"event_type":      eventType,
			"agent_id":        agentID,
			"action":          action,
			"outcome":         outcome,
			"sequence_number": seq,
		}
		content, _ := json.Marshal(eventData)

		entries = append(entries, crypto.AuditEntry{
			EntryHash: entryHash,
			PrevHash:  prevHash,
			Content:   content,
		})
		sequences = append(sequences, seq)
	}

	if len(entries) == 0 {
		return &audit.VerifyChainResponse{IsValid: true, BrokenAtSequence: -1}, nil
	}

	valid, breakIdx := crypto.VerifyChain(entries)
	var brokenAt int64 = -1
	if !valid && breakIdx >= 0 {
		brokenAt = int64(sequences[breakIdx])
	}

	return &audit.VerifyChainResponse{
		IsValid:          valid,
		BrokenAtSequence: brokenAt,
	}, nil
}

func (s *Server) GetEvents(req *audit.GetEventsRequest, stream audit.AuditLogService_GetEventsServer) error {
	return status.Errorf(codes.Unimplemented, "method GetEvents not implemented")
}

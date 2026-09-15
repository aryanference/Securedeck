package broker

import (
	"context"
	"crypto/ed25519"
	"strings"
	"time"

	brokerv1 "github.com/aryanference/securedeck/gen/go/broker/v1"
	"github.com/aryanference/securedeck/internal/crypto"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	brokerv1.UnimplementedCredentialBrokerServiceServer
	db         db.DB
	signingKey ed25519.PrivateKey
	revCache   *RevocationCache
}

func NewServer(database db.DB, signingKey ed25519.PrivateKey, revCache *RevocationCache) *Server {
	return &Server{
		db:         database,
		signingKey: signingKey,
		revCache:   revCache,
	}
}

func (s *Server) RegisterAgent(ctx context.Context, req *brokerv1.RegisterAgentRequest) (*brokerv1.RegisterAgentResponse, error) {
	agentID := uuid.New().String()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to begin tx: %v", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO agents (id, name, description, org_id) VALUES (?, ?, ?, ?)",
		agentID, req.Name, req.Description, req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to insert agent: %v", err)
	}

	for _, scope := range req.InitialScopes {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO agent_scopes (id, agent_id, scope, granted_by) VALUES (?, ?, ?, ?)",
			uuid.New().String(), agentID, scope, "system")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to insert scope: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to commit: %v", err)
	}

	return &brokerv1.RegisterAgentResponse{AgentId: agentID}, nil
}

func (s *Server) IssueToken(ctx context.Context, req *brokerv1.IssueTokenRequest) (*brokerv1.IssueTokenResponse, error) {
	var statusStr string
	err := s.db.QueryRowContext(ctx, "SELECT status FROM agents WHERE id = ?", req.AgentId).Scan(&statusStr)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "agent not found: %v", err)
	}
	if statusStr != "active" {
		return nil, status.Errorf(codes.PermissionDenied, "agent is not active")
	}

	rows, err := s.db.QueryContext(ctx, "SELECT scope FROM agent_scopes WHERE agent_id = ?", req.AgentId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query scopes: %v", err)
	}
	defer rows.Close()

	grantedScopes := make(map[string]bool)
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err == nil {
			grantedScopes[sc] = true
		}
	}

	for _, reqScope := range req.RequestedScopes {
		if !grantedScopes[reqScope] {
			return nil, status.Errorf(codes.PermissionDenied, "scope not granted: %s", reqScope)
		}
	}

	jti := uuid.New().String()
	ttl := 1 * time.Hour

	tokenStr, err := crypto.IssueToken(req.AgentId, req.RequestedScopes, ttl, s.signingKey, jti)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue token: %v", err)
	}

	scopesStr := strings.Join(req.RequestedScopes, ",")
	exp := time.Now().Add(ttl)

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO token_issuance_log (id, token_id, agent_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?)",
		uuid.New().String(), jti, req.AgentId, scopesStr, exp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to log issuance: %v", err)
	}

	return &brokerv1.IssueTokenResponse{
		Token:     tokenStr,
		ExpiresAt: timestamppb.New(exp),
	}, nil
}

func (s *Server) ValidateToken(ctx context.Context, req *brokerv1.ValidateTokenRequest) (*brokerv1.ValidateTokenResponse, error) {
	pub := s.signingKey.Public().(ed25519.PublicKey)
	claims, err := crypto.ValidateToken(req.Token, pub)
	if err != nil {
		return &brokerv1.ValidateTokenResponse{IsValid: false}, nil
	}

	if s.revCache != nil && s.revCache.IsRevoked(claims.JTI) {
		return &brokerv1.ValidateTokenResponse{IsValid: false}, nil
	}

	return &brokerv1.ValidateTokenResponse{
		IsValid: true,
		AgentId: claims.AgentID,
		Scopes:  claims.Scopes,
	}, nil
}

func (s *Server) RevokeToken(ctx context.Context, req *brokerv1.RevokeTokenRequest) (*brokerv1.RevokeTokenResponse, error) {
	_, err := s.db.ExecContext(ctx,
		"UPDATE token_issuance_log SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE token_id = ?",
		time.Now(), req.Reason, req.TokenId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke token: %v", err)
	}
	return &brokerv1.RevokeTokenResponse{}, nil
}

func (s *Server) RevokeAllForAgent(ctx context.Context, req *brokerv1.RevokeAllForAgentRequest) (*brokerv1.RevokeAllForAgentResponse, error) {
	_, err := s.db.ExecContext(ctx,
		"UPDATE token_issuance_log SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE agent_id = ? AND revoked = 0",
		time.Now(), req.Reason, req.AgentId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke tokens: %v", err)
	}
	return &brokerv1.RevokeAllForAgentResponse{}, nil
}

func (s *Server) MassRevoke(ctx context.Context, req *brokerv1.MassRevokeRequest) (*brokerv1.MassRevokeResponse, error) {
	_, err := s.db.ExecContext(ctx,
		"UPDATE token_issuance_log SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE revoked = 0",
		time.Now(), req.Reason)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to mass revoke: %v", err)
	}
	return &brokerv1.MassRevokeResponse{}, nil
}

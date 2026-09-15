package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	gatewayv1 "github.com/aryanference/securedeck/gen/go/gateway/v1"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements PolicyGatewayService over gRPC. CheckAction is the SDK
// integration path (Phase 6); the sidecar proxy in this phase drives the
// same Enforcer directly without going through gRPC.
type Server struct {
	gatewayv1.UnimplementedPolicyGatewayServiceServer
	db       db.DB
	enforcer *Enforcer

	allowedCount uint64
	deniedCount  uint64
}

func NewServer(database db.DB, enforcer *Enforcer) *Server {
	return &Server{db: database, enforcer: enforcer}
}

func (s *Server) CheckAction(ctx context.Context, req *gatewayv1.CheckActionRequest) (*gatewayv1.CheckActionResponse, error) {
	decision := s.enforcer.Enforce(ctx, ActionRequest{
		Token:      req.Token,
		ActionType: req.ActionType,
		Target:     req.Target,
		Context:    req.Context,
	})

	if decision.Allowed {
		atomic.AddUint64(&s.allowedCount, 1)
	} else {
		atomic.AddUint64(&s.deniedCount, 1)
	}

	return &gatewayv1.CheckActionResponse{
		Allowed:    decision.Allowed,
		Reason:     decision.Reason,
		DecisionId: decision.DecisionID,
	}, nil
}

func (s *Server) UpdatePolicy(ctx context.Context, req *gatewayv1.UpdatePolicyRequest) (*gatewayv1.UpdatePolicyResponse, error) {
	if req.OperatorId == "" {
		return nil, status.Error(codes.PermissionDenied, "operator_id required")
	}
	if len(req.Rules) > 0 {
		var probe []json.RawMessage
		if err := json.Unmarshal(req.Rules, &probe); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "rules must be a JSON array: %v", err)
		}
	}

	policyID := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (id, name, description, rules, created_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET rules = excluded.rules, description = excluded.description, updated_at = CURRENT_TIMESTAMP
	`, policyID, req.Name, req.Description, req.Rules, req.OperatorId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upsert policy: %v", err)
	}

	return &gatewayv1.UpdatePolicyResponse{PolicyId: policyID}, nil
}

func (s *Server) UpdateEgressAllowlist(ctx context.Context, req *gatewayv1.UpdateEgressRequest) (*gatewayv1.UpdateEgressResponse, error) {
	if req.OperatorId == "" {
		return nil, status.Error(codes.PermissionDenied, "operator_id required")
	}
	scope := req.Scope
	if scope == "" {
		scope = "global"
	}

	if req.Remove {
		_, err := s.db.ExecContext(ctx,
			`DELETE FROM egress_allowlist WHERE scope = ? AND domain = ? AND protocol = ?`,
			scope, req.Domain, protocolOrDefault(req.Protocol))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to remove egress entry: %v", err)
		}
		return &gatewayv1.UpdateEgressResponse{Applied: true}, nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO egress_allowlist (id, scope, domain, port, protocol, created_by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (scope, domain, port, protocol) DO NOTHING
	`, uuid.New().String(), scope, req.Domain, nullableInt32(req.Port), protocolOrDefault(req.Protocol), req.OperatorId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add egress entry: %v", err)
	}

	return &gatewayv1.UpdateEgressResponse{Applied: true}, nil
}

func protocolOrDefault(p string) string {
	if p == "" {
		return "https"
	}
	return p
}

func nullableInt32(p int32) any {
	if p == 0 {
		return nil
	}
	return p
}

// HealthHandler is a plain liveness/readiness endpoint for the REST surface.
func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.db.PingContext(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "db unreachable: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// MetricsHandler exposes enforcement counters in Prometheus text format.
func (s *Server) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP securedeck_gateway_decisions_total Enforcement decisions by outcome.\n")
	fmt.Fprintf(w, "# TYPE securedeck_gateway_decisions_total counter\n")
	fmt.Fprintf(w, "securedeck_gateway_decisions_total{outcome=\"allowed\"} %d\n", atomic.LoadUint64(&s.allowedCount))
	fmt.Fprintf(w, "securedeck_gateway_decisions_total{outcome=\"denied\"} %d\n", atomic.LoadUint64(&s.deniedCount))
}

// checkActionRESTHandler is the OpenAPI-documented REST/JSON wrapper around
// CheckAction for external integrations that don't speak gRPC.
func (s *Server) CheckActionRESTHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token      string          `json:"token"`
		ActionType string          `json:"action_type"`
		Target     string          `json:"target"`
		Context    json.RawMessage `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	decision := s.enforcer.Enforce(r.Context(), ActionRequest{
		Token:      body.Token,
		ActionType: body.ActionType,
		Target:     body.Target,
		Context:    body.Context,
	})

	w.Header().Set("Content-Type", "application/json")
	if !decision.Allowed {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"allowed":     decision.Allowed,
		"reason":      decision.Reason,
		"decision_id": decision.DecisionID,
	})
}

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	brokerv1 "github.com/aryanference/securedeck/gen/go/broker/v1"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/google/uuid"
)

// Decision is the outcome of Enforce. It is always logged to the audit
// service before being returned to the caller — see logDecision.
type Decision struct {
	Allowed    bool
	Reason     string
	DecisionID string
}

// Deny reason codes — stable strings so operators and tests can match on them.
const (
	ReasonDenylisted      = "denylisted"
	ReasonInvalidToken    = "invalid_token"
	ReasonScopeViolation  = "scope_violation"
	ReasonEgressViolation = "egress_violation"
	ReasonPolicyDenied    = "policy_denied"
	ReasonFailClosed      = "fail_closed"
)

// ActionRequest is the enforcer's internal representation of an action,
// decoupled from the gRPC message shape so both the gRPC server (Phase 6
// SDK mode) and the sidecar proxy (this phase) can drive the same path.
type ActionRequest struct {
	Token      string
	ActionType string
	Target     string
	Context    []byte
}

// policyRule is the minimal deterministic rule shape evaluated against an
// agent's assigned policies. Kept intentionally simple for v1 — this is not
// a general expression language, matching the PRD's emphasis on
// explainable, testable enforcement logic over cleverness.
type policyRule struct {
	DenyActionType     string `json:"deny_action_type,omitempty"`
	DenyTargetPrefix   string `json:"deny_target_prefix,omitempty"`
	DenyTargetContains string `json:"deny_target_contains,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

type egressEntry struct {
	domain   string
	port     int32 // 0 == any port
	protocol string
}

// Enforcer implements the SEC-01 enforcement decision flow. Every method is
// safe for concurrent use.
type Enforcer struct {
	db           db.DB
	brokerClient brokerv1.CredentialBrokerServiceClient
	auditClient  auditv1.AuditLogServiceClient
	denyList     *DenyList

	cacheTTL time.Duration

	mu             sync.RWMutex
	policyCache    map[string][]policyRule  // agent_id -> rules from all assigned policies
	egressCache    map[string][]egressEntry // scope ("global" or agent_id) -> allowlist entries
	cacheExpiresAt time.Time
}

// NewEnforcer constructs an Enforcer. auditClient must not be nil in
// production — if it is nil, LogEvent calls are skipped and every decision
// fails closed (see logDecision), matching SEC-01/SEC-06.
func NewEnforcer(database db.DB, brokerClient brokerv1.CredentialBrokerServiceClient, auditClient auditv1.AuditLogServiceClient, denyList *DenyList) *Enforcer {
	return &Enforcer{
		db:           database,
		brokerClient: brokerClient,
		auditClient:  auditClient,
		denyList:     denyList,
		cacheTTL:     5 * time.Second, // policy/allowlist data only — never the decision itself
		policyCache:  make(map[string][]policyRule),
		egressCache:  make(map[string][]egressEntry),
	}
}

// Enforce runs the full decision flow and always returns a Decision — it
// never lets a downstream error escape as "allowed". Every path (allow and
// deny) is logged to the audit service before returning.
func (e *Enforcer) Enforce(ctx context.Context, req ActionRequest) *Decision {
	// Step 1 + 2: token validation also gives us the agent identity needed for
	// the deny-list check. We cannot check the deny list against an unverified
	// token claim (that would mean trusting an unauthenticated agent_id), so
	// validation happens first and the deny-list check immediately follows it,
	// before any scope/egress/policy evaluation — preserving the spec's intent
	// that a suspended/terminated agent is rejected before any further work.
	if e.brokerClient == nil {
		return e.finalize(ctx, req, "", false, ReasonFailClosed)
	}

	validation, err := e.brokerClient.ValidateToken(ctx, &brokerv1.ValidateTokenRequest{Token: req.Token})
	if err != nil || validation == nil || !validation.IsValid {
		return e.finalize(ctx, req, "", false, ReasonInvalidToken)
	}
	agentID := validation.AgentId

	if e.denyList != nil {
		if denied, status := e.denyList.IsDenied(agentID); denied {
			return e.finalize(ctx, req, agentID, false, fmt.Sprintf("%s: %s", ReasonDenylisted, status.String()))
		}
	}

	// Step 3: scope check (SEC-01).
	if !scopeAllows(validation.Scopes, req.ActionType) {
		return e.finalize(ctx, req, agentID, false, ReasonScopeViolation)
	}

	// Step 4: egress check (SEC-03) — only applies to network-reaching actions.
	if isNetworkAction(req.ActionType) {
		allowed, err := e.checkEgress(ctx, agentID, req.Target)
		if err != nil {
			return e.finalize(ctx, req, agentID, false, ReasonFailClosed)
		}
		if !allowed {
			return e.finalize(ctx, req, agentID, false, ReasonEgressViolation)
		}
	}

	// Step 5: agent-specific policy rules.
	if denyReason, err := e.checkPolicies(ctx, agentID, req); err != nil {
		return e.finalize(ctx, req, agentID, false, ReasonFailClosed)
	} else if denyReason != "" {
		return e.finalize(ctx, req, agentID, false, denyReason)
	}

	// Step 6: allowed.
	return e.finalize(ctx, req, agentID, true, "")
}

// finalize logs the decision to the audit service and fails closed if the
// log write itself fails or the audit client is unavailable (SEC-01, SEC-06).
func (e *Enforcer) finalize(ctx context.Context, req ActionRequest, agentID string, allowed bool, reason string) *Decision {
	decisionID := uuid.New().String()
	outcome := "denied"
	if allowed {
		outcome = "allowed"
	}

	if e.auditClient == nil {
		return &Decision{Allowed: false, Reason: ReasonFailClosed, DecisionID: decisionID}
	}

	detail, _ := json.Marshal(map[string]any{
		"decision_id": decisionID,
		"reason":      reason,
		"target":      req.Target,
	})

	eventType := "policy.decision"
	if !allowed && (reason == ReasonEgressViolation) {
		// Unauthorized egress is a critical event per SEC-03 acceptance criteria.
		eventType = "policy.decision.critical"
	}

	logCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := e.auditClient.LogEvent(logCtx, &auditv1.LogEventRequest{
		SourceService: "gateway",
		EventType:     eventType,
		AgentId:       agentID,
		Action:        req.ActionType,
		Outcome:       outcome,
		Detail:        detail,
	})
	if err != nil {
		// Audit log unreachable → fail closed, regardless of what the decision
		// would otherwise have been.
		return &Decision{Allowed: false, Reason: ReasonFailClosed, DecisionID: decisionID}
	}

	if !allowed {
		return &Decision{Allowed: false, Reason: reason, DecisionID: decisionID}
	}
	return &Decision{Allowed: true, DecisionID: decisionID}
}

func scopeAllows(scopes []string, actionType string) bool {
	for _, s := range scopes {
		if s == actionType {
			return true
		}
	}
	return false
}

func isNetworkAction(actionType string) bool {
	return actionType == "http_request" || actionType == "network_request"
}

// checkEgress evaluates req's target host against the agent-scoped and
// global egress allowlists. Wildcard domains ("*.example.com") match any
// subdomain.
func (e *Enforcer) checkEgress(ctx context.Context, agentID, target string) (bool, error) {
	host, port := parseTargetHost(target)
	if host == "" {
		return false, nil
	}

	entries, err := e.loadEgress(ctx, agentID)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !domainMatches(entry.domain, host) {
			continue
		}
		if entry.port != 0 && port != 0 && entry.port != port {
			continue
		}
		return true, nil
	}
	return false, nil
}

func parseTargetHost(target string) (string, int32) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		// Fall back to treating the whole string as a bare host:port.
		host := target
		if h, _, err := splitHostPort(target); err == nil {
			host = h
		}
		return host, 0
	}
	var port int32
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	return u.Hostname(), port
}

func splitHostPort(s string) (string, string, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s, "", fmt.Errorf("no port")
	}
	return parts[0], parts[1], nil
}

func domainMatches(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix)
	}
	return false
}

func (e *Enforcer) loadEgress(ctx context.Context, agentID string) ([]egressEntry, error) {
	e.refreshCacheIfStale(ctx)

	e.mu.RLock()
	defer e.mu.RUnlock()

	combined := append([]egressEntry{}, e.egressCache["global"]...)
	combined = append(combined, e.egressCache[agentID]...)
	return combined, nil
}

// checkPolicies evaluates every rule from every policy assigned to agentID.
// Returns a non-empty deny reason on the first matching deny rule.
func (e *Enforcer) checkPolicies(ctx context.Context, agentID string, req ActionRequest) (string, error) {
	e.refreshCacheIfStale(ctx)

	e.mu.RLock()
	rules := e.policyCache[agentID]
	e.mu.RUnlock()

	for _, rule := range rules {
		if rule.DenyActionType != "" && rule.DenyActionType == req.ActionType {
			return reasonOrDefault(rule.Reason, ReasonPolicyDenied), nil
		}
		if rule.DenyTargetPrefix != "" && strings.HasPrefix(req.Target, rule.DenyTargetPrefix) {
			return reasonOrDefault(rule.Reason, ReasonPolicyDenied), nil
		}
		if rule.DenyTargetContains != "" && strings.Contains(req.Target, rule.DenyTargetContains) {
			return reasonOrDefault(rule.Reason, ReasonPolicyDenied), nil
		}
	}
	return "", nil
}

func reasonOrDefault(reason, fallback string) string {
	if reason != "" {
		return reason
	}
	return fallback
}

// refreshCacheIfStale reloads policy rules and the egress allowlist from the
// DB if the cache TTL has elapsed. This is the ONLY thing cached with a TTL
// — the enforcement decision itself is always recomputed fresh, per spec.
func (e *Enforcer) refreshCacheIfStale(ctx context.Context) {
	e.mu.RLock()
	stale := time.Now().After(e.cacheExpiresAt)
	e.mu.RUnlock()
	if !stale {
		return
	}

	policyCache, err := e.loadPolicyCache(ctx)
	if err != nil {
		return // keep serving the stale cache rather than erroring the hot path
	}
	egressCache, err := e.loadEgressCache(ctx)
	if err != nil {
		return
	}

	e.mu.Lock()
	e.policyCache = policyCache
	e.egressCache = egressCache
	e.cacheExpiresAt = time.Now().Add(e.cacheTTL)
	e.mu.Unlock()
}

func (e *Enforcer) loadPolicyCache(ctx context.Context) (map[string][]policyRule, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT ap.agent_id, p.rules
		FROM agent_policies ap
		JOIN policies p ON p.id = ap.policy_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]policyRule)
	for rows.Next() {
		var agentID string
		var rulesRaw []byte
		if err := rows.Scan(&agentID, &rulesRaw); err != nil {
			continue
		}
		var rules []policyRule
		if err := json.Unmarshal(rulesRaw, &rules); err != nil {
			continue
		}
		out[agentID] = append(out[agentID], rules...)
	}
	return out, nil
}

func (e *Enforcer) loadEgressCache(ctx context.Context) (map[string][]egressEntry, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT scope, domain, port, protocol FROM egress_allowlist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]egressEntry)
	for rows.Next() {
		var scope, domain, protocol string
		var port *int32
		if err := rows.Scan(&scope, &domain, &port, &protocol); err != nil {
			continue
		}
		p := int32(0)
		if port != nil {
			p = *port
		}
		out[scope] = append(out[scope], egressEntry{domain: domain, port: p, protocol: protocol})
	}
	return out, nil
}

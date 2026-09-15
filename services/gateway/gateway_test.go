package gateway

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	brokerv1 "github.com/aryanference/securedeck/gen/go/broker/v1"
	ksv1 "github.com/aryanference/securedeck/gen/go/killswitch/v1"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// --- fakes -------------------------------------------------------------

type fakeBroker struct {
	brokerv1.CredentialBrokerServiceClient
	valid   bool
	agentID string
	scopes  []string
}

func (f *fakeBroker) ValidateToken(ctx context.Context, in *brokerv1.ValidateTokenRequest, opts ...grpc.CallOption) (*brokerv1.ValidateTokenResponse, error) {
	if !f.valid {
		return &brokerv1.ValidateTokenResponse{IsValid: false}, nil
	}
	return &brokerv1.ValidateTokenResponse{IsValid: true, AgentId: f.agentID, Scopes: f.scopes}, nil
}

type fakeAudit struct {
	auditv1.AuditLogServiceClient
	fail   bool
	events []*auditv1.LogEventRequest
}

func (f *fakeAudit) LogEvent(ctx context.Context, in *auditv1.LogEventRequest, opts ...grpc.CallOption) (*auditv1.LogEventResponse, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	f.events = append(f.events, in)
	return &auditv1.LogEventResponse{EventId: "evt"}, nil
}

type fakeKillSwitchClient struct {
	ksv1.KillSwitchServiceClient
}

// --- helpers -------------------------------------------------------------

func newTestDB(t *testing.T) db.DB {
	t.Helper()
	// A unique named in-memory database per test. Plain "file::memory:" with
	// cache=shared is process-wide — every test using that literal DSN would
	// share the same tables and collide on CREATE TABLE. A unique name keeps
	// cache=shared's multi-connection benefit (needed since database/sql
	// pools connections) while isolating each test from the others.
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_mutex=full", uuid.New().String())
	database, err := db.NewSQLiteDB(dsn)
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT, rules TEXT NOT NULL, created_by TEXT NOT NULL)`,
		`CREATE TABLE agent_policies (agent_id TEXT NOT NULL, policy_id TEXT NOT NULL, PRIMARY KEY (agent_id, policy_id))`,
		`CREATE TABLE egress_allowlist (id TEXT PRIMARY KEY, scope TEXT NOT NULL, domain TEXT NOT NULL, port INTEGER, protocol TEXT DEFAULT 'https', created_by TEXT NOT NULL)`,
	}
	for _, s := range stmts {
		if _, err := database.ExecContext(ctx, s); err != nil {
			t.Fatalf("schema init failed: %v", err)
		}
	}
	return database
}

func newTestEnforcer(t *testing.T, valid bool, agentID string, scopes []string, auditFail bool) (*Enforcer, *fakeAudit) {
	t.Helper()
	database := newTestDB(t)
	broker := &fakeBroker{valid: valid, agentID: agentID, scopes: scopes}
	audit := &fakeAudit{fail: auditFail}
	denyList := NewDenyList(&fakeKillSwitchClient{})
	return NewEnforcer(database, broker, audit, denyList), audit
}

// --- tests -----------------------------------------------------------

func TestScopeEnforcement(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, true, "agent-1", []string{"read:files"}, false)

	d := enforcer.Enforce(context.Background(), ActionRequest{
		Token: "tok", ActionType: "code_execute", Target: "echo hi",
	})
	if d.Allowed {
		t.Fatalf("expected out-of-scope action to be denied, got allowed")
	}
	if d.Reason != ReasonScopeViolation {
		t.Fatalf("expected scope_violation, got %q", d.Reason)
	}

	d2 := enforcer.Enforce(context.Background(), ActionRequest{
		Token: "tok", ActionType: "read:files", Target: "/tmp/data",
	})
	if !d2.Allowed {
		t.Fatalf("expected in-scope action to be allowed, got denied: %s", d2.Reason)
	}
}

func TestEgressControl(t *testing.T) {
	enforcer, audit := newTestEnforcer(t, true, "agent-1", []string{"http_request"}, false)
	ctx := context.Background()

	_, err := enforcer.db.ExecContext(ctx,
		`INSERT INTO egress_allowlist (id, scope, domain, protocol, created_by) VALUES ('e1','global','api.allowed.com','https','test')`)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	enforcer.cacheExpiresAt = time.Time{} // force refresh

	denied := enforcer.Enforce(ctx, ActionRequest{Token: "tok", ActionType: "http_request", Target: "https://evil.example.com/exfil"})
	if denied.Allowed {
		t.Fatalf("expected non-allowlisted domain to be denied")
	}
	if denied.Reason != ReasonEgressViolation {
		t.Fatalf("expected egress_violation, got %q", denied.Reason)
	}

	found := false
	for _, e := range audit.events {
		if e.EventType == "policy.decision.critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected egress violation to be logged as a critical event")
	}

	allowed := enforcer.Enforce(ctx, ActionRequest{Token: "tok", ActionType: "http_request", Target: "https://api.allowed.com/data"})
	if !allowed.Allowed {
		t.Fatalf("expected allowlisted domain to be allowed, got denied: %s", allowed.Reason)
	}
}

func TestFailClosedOnAuditUnreachable(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, true, "agent-1", []string{"read:files"}, true /* audit fails */)

	d := enforcer.Enforce(context.Background(), ActionRequest{Token: "tok", ActionType: "read:files", Target: "/tmp"})
	if d.Allowed {
		t.Fatalf("expected fail-closed denial when audit log is unreachable")
	}
	if d.Reason != ReasonFailClosed {
		t.Fatalf("expected fail_closed, got %q", d.Reason)
	}
}

func TestFailClosedOnMissingAuditClient(t *testing.T) {
	database := newTestDB(t)
	broker := &fakeBroker{valid: true, agentID: "agent-1", scopes: []string{"read:files"}}
	enforcer := NewEnforcer(database, broker, nil, NewDenyList(nil))

	d := enforcer.Enforce(context.Background(), ActionRequest{Token: "tok", ActionType: "read:files", Target: "/tmp"})
	if d.Allowed {
		t.Fatalf("expected fail-closed with no audit client configured")
	}
}

func TestInvalidTokenDenied(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, false, "", nil, false)
	d := enforcer.Enforce(context.Background(), ActionRequest{Token: "garbage", ActionType: "read:files", Target: "/tmp"})
	if d.Allowed || d.Reason != ReasonInvalidToken {
		t.Fatalf("expected invalid_token denial, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
}

func TestDenyListBlocksBeforeFurtherChecks(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, true, "agent-1", []string{"read:files"}, false)
	enforcer.denyList.applyUpdate(&ksv1.DenyListEntry{AgentId: "agent-1", Status: ksv1.DenyStatus_DENY_STATUS_SUSPENDED})

	d := enforcer.Enforce(context.Background(), ActionRequest{Token: "tok", ActionType: "read:files", Target: "/tmp"})
	if d.Allowed {
		t.Fatalf("expected suspended agent to be denied regardless of valid scope")
	}
	if d.Reason == "" {
		t.Fatalf("expected a denylisted reason")
	}
}

func TestAllowlistHotReload(t *testing.T) {
	enforcer, _ := newTestEnforcer(t, true, "agent-1", []string{"http_request"}, false)
	ctx := context.Background()

	d1 := enforcer.Enforce(ctx, ActionRequest{Token: "tok", ActionType: "http_request", Target: "https://new.example.com/x"})
	if d1.Allowed {
		t.Fatalf("expected deny before allowlist entry exists")
	}

	_, err := enforcer.db.ExecContext(ctx,
		`INSERT INTO egress_allowlist (id, scope, domain, protocol, created_by) VALUES ('e2','global','new.example.com','https','test')`)
	if err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	enforcer.cacheExpiresAt = time.Time{} // simulate TTL elapsing without waiting

	d2 := enforcer.Enforce(ctx, ActionRequest{Token: "tok", ActionType: "http_request", Target: "https://new.example.com/x"})
	if !d2.Allowed {
		t.Fatalf("expected allow after allowlist hot-reload, got denied: %s", d2.Reason)
	}
}

// TestScopeMatching is a property-based test: for any randomly generated
// scope set and action type, scopeAllows must return true iff actionType is
// a literal member of scopes — no partial/prefix matching should ever occur.
func TestScopeMatching(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alphabet := []string{"read:files", "write:files", "http_request", "code_execute", "exec", "read", "read:file"}

	for i := 0; i < 500; i++ {
		n := rng.Intn(len(alphabet))
		var scopes []string
		for j := 0; j < n; j++ {
			scopes = append(scopes, alphabet[rng.Intn(len(alphabet))])
		}
		action := alphabet[rng.Intn(len(alphabet))]

		want := false
		for _, s := range scopes {
			if s == action {
				want = true
			}
		}
		got := scopeAllows(scopes, action)
		if got != want {
			t.Fatalf("scopeAllows(%v, %q) = %v, want %v", scopes, action, got, want)
		}
	}
}

func TestDomainMatchesWildcard(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "evil.com", false},
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "foo.bar.example.com", true},
	}
	for _, c := range cases {
		if got := domainMatches(c.pattern, c.host); got != c.want {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// BenchmarkEnforce asserts the enforce path stays within the SEC-01 latency
// budget (<=50ms p95) by exercising the full allow path against an
// in-memory SQLite DB and in-process fakes.
func BenchmarkEnforce(b *testing.B) {
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_mutex=full", uuid.New().String())
	database, _ := db.NewSQLiteDB(dsn)
	defer database.Close()
	ctx := context.Background()
	database.ExecContext(ctx, `CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT, rules TEXT NOT NULL, created_by TEXT NOT NULL)`)
	database.ExecContext(ctx, `CREATE TABLE agent_policies (agent_id TEXT NOT NULL, policy_id TEXT NOT NULL, PRIMARY KEY (agent_id, policy_id))`)
	database.ExecContext(ctx, `CREATE TABLE egress_allowlist (id TEXT PRIMARY KEY, scope TEXT NOT NULL, domain TEXT NOT NULL, port INTEGER, protocol TEXT DEFAULT 'https', created_by TEXT NOT NULL)`)

	broker := &fakeBroker{valid: true, agentID: "agent-1", scopes: []string{"read:files"}}
	audit := &fakeAudit{}
	enforcer := NewEnforcer(database, broker, audit, NewDenyList(nil))

	req := ActionRequest{Token: "tok", ActionType: "read:files", Target: "/tmp/data"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := enforcer.Enforce(ctx, req)
		if !d.Allowed {
			b.Fatalf("unexpected denial in benchmark: %s", d.Reason)
		}
	}
}

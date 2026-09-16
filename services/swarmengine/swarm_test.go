package swarmengine

import (
	"testing"
	"time"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSplitPrivilegeDetection(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	
	event1 := &auditv1.AuditEvent{
		EventId: "ev1", AgentId: "agentA", Action: "file_read", Timestamp: timestamppb.Now(),
	}
	event2 := &auditv1.AuditEvent{
		EventId: "ev2", AgentId: "agentB", Action: "network_write", Timestamp: timestamppb.Now(),
	}
	
	res1 := engine.ProcessEvent(event1)
	if res1 != nil { t.Fatalf("Expected no alert on first standalone event") }
	
	res2 := engine.ProcessEvent(event2)
	if res2 == nil { t.Fatalf("Expected split-privilege alert on second event [SEC-09]") }
	if len(res2.AgentIds) != 2 { t.Fatalf("Expected exactly 2 agents involved in correlation") }
}

func TestFalsePositiveSameAgent(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	
	event1 := &auditv1.AuditEvent{
		EventId: "ev1", AgentId: "agentA", Action: "file_read", Timestamp: timestamppb.Now(),
	}
	event2 := &auditv1.AuditEvent{
		EventId: "ev2", AgentId: "agentA", Action: "network_write", Timestamp: timestamppb.Now(),
	}
	
	engine.ProcessEvent(event1)
	// If the same agent does both, individual Gateway rules catch it, not the Swarm Engine
	if engine.ProcessEvent(event2) != nil { 
		t.Fatalf("Expected no alert for the same agent executing both actions") 
	}
}

func TestTimeWindowExpiry(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	oldTime := timestamppb.New(time.Now().Add(-10 * time.Minute))
	
	event1 := &auditv1.AuditEvent{
		EventId: "ev1", AgentId: "agentA", Action: "file_read", Timestamp: oldTime,
	}
	event2 := &auditv1.AuditEvent{
		EventId: "ev2", AgentId: "agentB", Action: "network_write", Timestamp: timestamppb.Now(),
	}
	
	engine.ProcessEvent(event1)
	// The first event is 10 minutes old, the correlation window is 5 minutes.
	if engine.ProcessEvent(event2) != nil { t.Fatalf("Expected no alert due to time window expiry") }
}

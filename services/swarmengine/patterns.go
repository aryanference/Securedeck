package swarmengine

import (
	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	swarmv1 "github.com/aryanference/securedeck/gen/go/swarm/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func EvaluatePatterns(g *Graph, newEvent *auditv1.AuditEvent) *swarmv1.SwarmAlert {
	edges := g.GetEdges()
	
	// Pattern V1: Split-privilege data exfiltration (SEC-09)
	// Agent A reads sensitive data, Agent B writes to network.
	// If the current event is a read or write, check the graph for its counterpart.
	
	isRead := newEvent.Action == "file_read" || newEvent.Action == "data_read"
	isWrite := newEvent.Action == "network_write" || newEvent.Action == "http_request"
	
	if isRead || isWrite {
		for _, e := range edges {
			// We only care if a DIFFERENT agent is performing the complementary action
			if e.AgentID != newEvent.AgentId {
				eIsRead := e.ActionType == "file_read" || e.ActionType == "data_read"
				eIsWrite := e.ActionType == "network_write" || e.ActionType == "http_request"
				
				if (isRead && eIsWrite) || (isWrite && eIsRead) {
					return &swarmv1.SwarmAlert{
						AlertId:          "swarm-alert-" + newEvent.EventId,
						AgentIds:         []string{newEvent.AgentId, e.AgentID},
						PatternId:        "split-privilege-exfil",
						Description:      "Multi-agent split-privilege data exfiltration detected",
						EvidenceEventIds: []string{newEvent.EventId, e.EventID},
						DetectedAt:       timestamppb.Now(),
					}
				}
			}
		}
	}

	// Additional patterns (Collaborative Scope Escalation, Fan-out Probing) 
	// would be evaluated sequentially here.
	return nil
}

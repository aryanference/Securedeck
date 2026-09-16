package swarmengine

import (
	"time"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	swarmv1 "github.com/aryanference/securedeck/gen/go/swarm/v1"
)

type Engine struct {
	Graph  *Graph
	Window time.Duration
}

func NewEngine(window time.Duration) *Engine {
	return &Engine{
		Graph:  NewGraph(),
		Window: window,
	}
}

func (e *Engine) ProcessEvent(event *auditv1.AuditEvent) *swarmv1.SwarmAlert {
	ts := event.Timestamp.AsTime()
	
	// 1. Expire old edges that fall outside the correlation window
	e.Graph.Expire(time.Now().Add(-e.Window))
	
	// 2. Add new edge (Agent -> Resource via Action)
	// Using string(Detail) as a simplified resource identifier for V1
	targetResource := string(event.Detail)
	if targetResource == "" { targetResource = "global" }
	e.Graph.AddEdge(event.AgentId, targetResource, event.Action, ts, event.EventId)
	
	// 3. Evaluate multi-agent patterns
	return EvaluatePatterns(e.Graph, event)
}

package swarmengine

import (
	"sync"
	"time"
)

type Edge struct {
	AgentID    string
	ResourceID string
	ActionType string
	Timestamp  time.Time
	EventID    string
}

type Graph struct {
	mu    sync.RWMutex
	edges []Edge
}

func NewGraph() *Graph {
	return &Graph{edges: make([]Edge, 0)}
}

func (g *Graph) AddEdge(agentID, resourceID, actionType string, ts time.Time, eventID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, Edge{agentID, resourceID, actionType, ts, eventID})
}

func (g *Graph) Expire(before time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var valid []Edge
	for _, e := range g.edges {
		if e.Timestamp.After(before) {
			valid = append(valid, e)
		}
	}
	g.edges = valid
}

func (g *Graph) GetEdges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	// Return a copy to prevent race conditions during pattern evaluation
	res := make([]Edge, len(g.edges))
	copy(res, g.edges)
	return res
}

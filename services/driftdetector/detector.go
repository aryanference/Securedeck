package driftdetector

import (
	"context"
	"log/slog"
	
	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	driftv1 "github.com/aryanference/securedeck/gen/go/drift/v1"
)

type Detector struct {
	rules []Rule
	tasks map[string]*TaskDescription
}

func NewDetector() *Detector {
	return &Detector{
		rules: GetEnabledRules(),
		tasks: make(map[string]*TaskDescription),
	}
}

func (d *Detector) RegisterTask(agentID string, task *TaskDescription) {
	d.tasks[agentID] = task
}

func (d *Detector) ProcessEvent(ctx context.Context, event *auditv1.AuditEvent, history []*auditv1.AuditEvent) *driftv1.DriftAlert {
	task, exists := d.tasks[event.AgentId]
	if !exists {
		return nil // No baseline to compare against
	}

	for _, rule := range d.rules {
		if alert := rule.Evaluate(event, task, history); alert != nil {
			slog.Info("Drift detected", "agent", event.AgentId, "rule", alert.RuleId)
			return alert
		}
	}
	return nil
}

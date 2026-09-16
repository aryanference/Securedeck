package driftdetector

import (
	"strings"
	
	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	driftv1 "github.com/aryanference/securedeck/gen/go/drift/v1"
)

type TaskDescription struct {
	Categories []string
	Keywords   []string
}

type Rule interface {
	Evaluate(event *auditv1.AuditEvent, task *TaskDescription, history []*auditv1.AuditEvent) *driftv1.DriftAlert
}

func GetEnabledRules() []Rule {
	return []Rule{
		&CategoryMismatchRule{},
		&InjectionPatternRule{},
		&FrequencyAnomalyRule{},
	}
}

// Rule 1: Category Mismatch (SEC-05)
type CategoryMismatchRule struct{}
func (r *CategoryMismatchRule) Evaluate(event *auditv1.AuditEvent, task *TaskDescription, history []*auditv1.AuditEvent) *driftv1.DriftAlert {
	if event.Action == "code_execute" && !contains(task.Categories, "research") {
		return buildAlert(event, "rule-01-category", "warning", "Action category deviates from declared task")
	}
	return nil
}

// Rule 2: Injected-Instruction Pattern (SEC-04)
type InjectionPatternRule struct{}
func (r *InjectionPatternRule) Evaluate(event *auditv1.AuditEvent, task *TaskDescription, history []*auditv1.AuditEvent) *driftv1.DriftAlert {
	target := string(event.Detail)
	if len(task.Keywords) > 0 && !containsAny(target, task.Keywords) {
		return buildAlert(event, "rule-02-injection", "critical", "Action indicates possible instruction hijack")
	}
	return nil
}

// Rule 3: Frequency Anomaly
type FrequencyAnomalyRule struct{}
func (r *FrequencyAnomalyRule) Evaluate(event *auditv1.AuditEvent, task *TaskDescription, history []*auditv1.AuditEvent) *driftv1.DriftAlert {
	if len(history) > 100 {
		return buildAlert(event, "rule-03-frequency", "warning", "Action rate anomaly detected")
	}
	return nil
}

func buildAlert(event *auditv1.AuditEvent, ruleID, severity, desc string) *driftv1.DriftAlert {
	return &driftv1.DriftAlert{
		AgentId:          event.AgentId,
		Severity:         severity,
		RuleId:           ruleID,
		Description:      desc,
		EvidenceEventIds: []string{event.EventId},
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func containsAny(target string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(target, kw) {
			return true
		}
	}
	return false
}

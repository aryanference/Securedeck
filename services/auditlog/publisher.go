package auditlog

import (
	"fmt"

	audit "github.com/aryanference/securedeck/gen/go/audit/v1"
	"github.com/aryanference/securedeck/internal/nats"
	"google.golang.org/protobuf/proto"
)

type Publisher struct {
	client *nats.Client
}

func NewPublisher(client *nats.Client) (*Publisher, error) {
	// Ensure the stream exists
	err := client.CreateStream("AUDIT", []string{"audit.events.>"})
	if err != nil {
		return nil, fmt.Errorf("failed to create audit stream: %w", err)
	}
	return &Publisher{client: client}, nil
}

func (p *Publisher) PublishEvent(event *audit.AuditEvent) error {
	data, err := proto.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	subject := fmt.Sprintf("audit.events.%s", event.EventType)
	return p.client.Publish(subject, data)
}

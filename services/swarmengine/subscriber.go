package swarmengine

import (
	"context"
	"log/slog"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
)

type Subscriber struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	engine *Engine
}

func NewSubscriber(natsURL string, engine *Engine) (*Subscriber, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil { return nil, err }
	
	js, err := nc.JetStream()
	if err != nil { return nil, err }

	return &Subscriber{
		nc:     nc,
		js:     js,
		engine: engine,
	}, nil
}

func (s *Subscriber) Start(ctx context.Context) error {
	// Important: Uses a separate durable consumer group ("swarmengine") 
	// so it doesn't compete with the Drift Detector for events.
	_, err := s.js.Subscribe("audit.events.>", func(m *nats.Msg) {
		var event auditv1.AuditEvent
		if err := proto.Unmarshal(m.Data, &event); err != nil {
			slog.Error("Failed to unmarshal audit event", "error", err)
			return
		}

		if alert := s.engine.ProcessEvent(&event); alert != nil {
			slog.Warn("Swarm alert generated", "pattern", alert.PatternId, "agents", len(alert.AgentIds))
			
			alertBytes, _ := proto.Marshal(alert)
			// Publish back to NATS for the Compliance/Console services to consume
			s.js.Publish("alerts.swarm", alertBytes)
		}
		
		m.Ack()
	}, nats.Durable("swarmengine"), nats.ManualAck())
	return err
}

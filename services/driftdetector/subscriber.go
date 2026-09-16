package driftdetector

import (
	"context"
	"log/slog"
	
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	
	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
)

type Subscriber struct {
	nc       *nats.Conn
	js       nats.JetStreamContext
	detector *Detector
	history  map[string][]*auditv1.AuditEvent
}

func NewSubscriber(natsURL string, d *Detector) (*Subscriber, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil { return nil, err }
	
	js, err := nc.JetStream()
	if err != nil { return nil, err }

	return &Subscriber{
		nc:       nc,
		js:       js,
		detector: d,
		history:  make(map[string][]*auditv1.AuditEvent),
	}, nil
}

func (s *Subscriber) Start(ctx context.Context) error {
	_, err := s.js.Subscribe("audit.events.>", func(m *nats.Msg) {
		var event auditv1.AuditEvent
		if err := proto.Unmarshal(m.Data, &event); err != nil {
			slog.Error("Failed to unmarshal audit event", "error", err)
			return
		}

		hist := s.history[event.AgentId]
		hist = append(hist, &event)
		if len(hist) > 101 { hist = hist[1:] }
		s.history[event.AgentId] = hist

		if alert := s.detector.ProcessEvent(ctx, &event, hist); alert != nil {
			slog.Info("Publishing drift alert", "alert_id", alert.AlertId)
		}
		m.Ack()
	}, nats.Durable("driftdetector"), nats.ManualAck())
	return err
}

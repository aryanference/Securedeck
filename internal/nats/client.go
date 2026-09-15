package nats

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type Client struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

func Connect(url string) (*Client, error) {
	nc, err := nats.Connect(url, nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nats: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("failed to get jetstream context: %w", err)
	}

	return &Client{nc: nc, js: js}, nil
}

func (c *Client) CreateStream(name string, subjects []string) error {
	_, err := c.js.AddStream(&nats.StreamConfig{
		Name:     name,
		Subjects: subjects,
		Storage:  nats.FileStorage,
	})
	if err != nil {
		if err.Error() == "stream name already in use" {
			return nil
		}
		return fmt.Errorf("failed to create stream: %w", err)
	}
	return nil
}

func (c *Client) Publish(subject string, data []byte) error {
	_, err := c.js.Publish(subject, data)
	return err
}

func (c *Client) Subscribe(subject string, handler func(msg *nats.Msg)) (*nats.Subscription, error) {
	return c.js.Subscribe(subject, handler, nats.Durable("default"))
}

func (c *Client) Close() {
	c.nc.Close()
}

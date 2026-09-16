package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aryanference/securedeck/services/swarmengine"
)

func main() {
	slog.Info("Starting Securedeck Swarm Correlation Engine")

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	// 5-minute sliding window for SEC-09 correlation graph
	engine := swarmengine.NewEngine(5 * time.Minute)
	
	sub, err := swarmengine.NewSubscriber(natsURL, engine)
	if err != nil {
		slog.Error("Failed to initialize NATS subscriber", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sub.Start(ctx); err != nil {
		slog.Error("Failed to start subscriber", "error", err)
		os.Exit(1)
	}

	slog.Info("Swarm Correlation Engine running. Subscribed to audit.events.>")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	
	slog.Info("Shutting down Swarm Correlation Engine")
}

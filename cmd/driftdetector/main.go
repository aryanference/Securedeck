package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aryanference/securedeck/services/driftdetector"
)

func main() {
	slog.Info("Starting Securedeck Drift Detector")

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	detector := driftdetector.NewDetector()
	
	sub, err := driftdetector.NewSubscriber(natsURL, detector)
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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	slog.Info("Shutting down Drift Detector")
}

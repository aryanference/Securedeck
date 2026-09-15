package nats

import (
	"fmt"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

func StartEmbeddedServer(dataDir string, port int) (*server.Server, error) {
	opts := &server.Options{
		JetStream: true,
		StoreDir:  dataDir,
		Port:      port,
	}

	ns, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize embedded nats: %w", err)
	}

	go ns.Start()
	
	if !ns.ReadyForConnections(10 * time.Second) {
		return nil, fmt.Errorf("embedded nats failed to start")
	}

	return ns, nil
}

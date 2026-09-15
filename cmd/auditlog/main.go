package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	audit "github.com/aryanference/securedeck/gen/go/audit/v1"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/aryanference/securedeck/internal/mtls"
	"github.com/aryanference/securedeck/internal/nats"
	"github.com/aryanference/securedeck/services/auditlog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// 1. Connect to DB
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN environment variable required")
	}

	var database db.DB
	var err error
	dialect := os.Getenv("DB_DIALECT")
	if dialect == "sqlite" {
		database, err = db.NewSQLiteDB(dsn)
	} else {
		database, err = db.NewPostgresDB(dsn)
	}
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	// 2. Run migrations
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		if dialect == "sqlite" {
			migrationsDir = "migrations/sqlite"
		} else {
			migrationsDir = "migrations/postgres"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.Migrate(ctx, database, migrationsDir, dialect); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// 3. Setup NATS
	var natsClient *nats.Client
	natsMode := os.Getenv("NATS_MODE")
	if natsMode == "embedded" || natsMode == "" {
		dataDir := os.Getenv("NATS_DATA_DIR")
		if dataDir == "" {
			dataDir = "./nats-data"
		}
		ns, err := nats.StartEmbeddedServer(dataDir, 4222)
		if err != nil {
			log.Fatalf("failed to start embedded nats: %v", err)
		}
		defer ns.Shutdown()
		
		natsClient, err = nats.Connect(ns.ClientURL())
		if err != nil {
			log.Fatalf("failed to connect to embedded nats: %v", err)
		}
	} else {
		natsURL := os.Getenv("NATS_URL")
		if natsURL == "" {
			natsURL = "nats://localhost:4222"
		}
		natsClient, err = nats.Connect(natsURL)
		if err != nil {
			log.Fatalf("failed to connect to nats: %v", err)
		}
	}
	defer natsClient.Close()

	publisher, err := auditlog.NewPublisher(natsClient)
	if err != nil {
		log.Fatalf("failed to create publisher: %v", err)
	}

	// 4. Start gRPC Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	caPath := os.Getenv("TLS_CA_PATH")
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	var grpcOpts []grpc.ServerOption
	if caPath != "" && certPath != "" && keyPath != "" {
		tlsConfig, err := mtls.LoadServerConfig(caPath, certPath, keyPath)
		if err != nil {
			log.Fatalf("failed to load tls config: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	auditServer := auditlog.NewServer(database, publisher)
	audit.RegisterAuditLogServiceServer(grpcServer, auditServer)

	go func() {
		log.Printf("auditlog service listening on %s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Wait for interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("shutting down gracefully...")
	grpcServer.GracefulStop()
}

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

	brokerv1 "github.com/aryanference/securedeck/gen/go/broker/v1"
	"github.com/aryanference/securedeck/internal/crypto"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/aryanference/securedeck/internal/mtls"
	brokersvc "github.com/aryanference/securedeck/services/broker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN required")
	}

	dialect := os.Getenv("DB_DIALECT")
	var database db.DB
	var err error
	if dialect == "sqlite" {
		database, err = db.NewSQLiteDB(dsn)
	} else {
		database, err = db.NewPostgresDB(dsn)
	}
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}
	defer database.Close()

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
		log.Fatalf("failed to migrate: %v", err)
	}

	keyPath := os.Getenv("SIGNING_KEY_PATH")
	if keyPath == "" {
		log.Fatal("SIGNING_KEY_PATH required")
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("failed to read signing key: %v", err)
	}
	signingKey, err := crypto.PEMToPrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("failed to parse signing key: %v", err)
	}

	revCache := brokersvc.NewRevocationCache(database, 5*time.Second)
	go revCache.Start(context.Background())

	port := os.Getenv("PORT")
	if port == "" {
		port = "50052"
	}
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	caPath := os.Getenv("TLS_CA_PATH")
	certPath := os.Getenv("TLS_CERT_PATH")
	srvKeyPath := os.Getenv("TLS_KEY_PATH")

	var grpcOpts []grpc.ServerOption
	if caPath != "" && certPath != "" && srvKeyPath != "" {
		tlsConfig, err := mtls.LoadServerConfig(caPath, certPath, srvKeyPath)
		if err != nil {
			log.Fatalf("failed to load tls config: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	brokerServer := brokersvc.NewServer(database, signingKey, revCache)
	brokerv1.RegisterCredentialBrokerServiceServer(grpcServer, brokerServer)

	go func() {
		log.Printf("broker listening on :%s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("shutting down gracefully...")
	grpcServer.GracefulStop()
}

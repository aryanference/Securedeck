package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auditv1 "github.com/aryanference/securedeck/gen/go/audit/v1"
	brokerv1 "github.com/aryanference/securedeck/gen/go/broker/v1"
	gatewayv1 "github.com/aryanference/securedeck/gen/go/gateway/v1"
	ksv1 "github.com/aryanference/securedeck/gen/go/killswitch/v1"
	"github.com/aryanference/securedeck/internal/db"
	"github.com/aryanference/securedeck/internal/mtls"
	"github.com/aryanference/securedeck/services/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// 1. Connect to DB
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN environment variable required")
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
	if err := db.Migrate(ctx, database, migrationsDir, dialect); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}
	cancel()

	// 3. Client-side mTLS (shared by all upstream gRPC connections)
	caPath := os.Getenv("TLS_CA_PATH")
	certPath := os.Getenv("TLS_CERT_PATH")
	keyPath := os.Getenv("TLS_KEY_PATH")

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if caPath != "" && certPath != "" && keyPath != "" {
		tlsConfig, err := mtls.LoadClientConfig(caPath, certPath, keyPath)
		if err != nil {
			log.Fatalf("failed to load client tls config: %v", err)
		}
		dialOpts = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	}

	// 4. Connect to Credential Broker (required — fail closed without it)
	brokerAddr := os.Getenv("BROKER_ADDR")
	if brokerAddr == "" {
		log.Fatal("BROKER_ADDR environment variable required")
	}
	brokerConn, err := grpc.NewClient(brokerAddr, dialOpts...)
	if err != nil {
		log.Fatalf("failed to dial broker: %v", err)
	}
	defer brokerConn.Close()
	brokerClient := brokerv1.NewCredentialBrokerServiceClient(brokerConn)

	// 5. Connect to Audit Log (required — fail closed without it)
	auditAddr := os.Getenv("AUDIT_ADDR")
	if auditAddr == "" {
		log.Fatal("AUDIT_ADDR environment variable required")
	}
	auditConn, err := grpc.NewClient(auditAddr, dialOpts...)
	if err != nil {
		log.Fatalf("failed to dial audit log: %v", err)
	}
	defer auditConn.Close()
	auditClient := auditv1.NewAuditLogServiceClient(auditConn)

	// 6. Connect to Kill Switch (OPTIONAL — an unreachable kill switch never
	// causes the gateway to fail closed; see services/gateway/denylist.go)
	var ksClient ksv1.KillSwitchServiceClient
	if ksAddr := os.Getenv("KILLSWITCH_ADDR"); ksAddr != "" {
		ksConn, err := grpc.NewClient(ksAddr, dialOpts...)
		if err != nil {
			log.Printf("warning: failed to dial kill switch, deny list will stay empty: %v", err)
		} else {
			defer ksConn.Close()
			ksClient = ksv1.NewKillSwitchServiceClient(ksConn)
		}
	}

	denyList := gateway.NewDenyList(ksClient)
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	go denyList.Start(bgCtx)

	enforcer := gateway.NewEnforcer(database, brokerClient, auditClient, denyList)
	gwServer := gateway.NewServer(database, enforcer)

	// 7. gRPC server (SDK mode, Phase 6 consumers dial this today)
	grpcPort := os.Getenv("PORT")
	if grpcPort == "" {
		grpcPort = "50053"
	}
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	var grpcOpts []grpc.ServerOption
	if caPath != "" && certPath != "" && keyPath != "" {
		serverTLS, err := mtls.LoadServerConfig(caPath, certPath, keyPath)
		if err != nil {
			log.Fatalf("failed to load server tls config: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	gatewayv1.RegisterPolicyGatewayServiceServer(grpcServer, gwServer)

	go func() {
		log.Printf("gateway grpc service listening on :%s", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve grpc: %v", err)
		}
	}()

	// 8. HTTP server: REST wrapper, health, metrics, sidecar proxy
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", gwServer.HealthHandler)
	mux.HandleFunc("/metrics", gwServer.MetricsHandler)
	mux.HandleFunc("/v1/check-action", gwServer.CheckActionRESTHandler)

	httpSrv := &http.Server{Addr: fmt.Sprintf(":%s", httpPort), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("gateway http (rest/health/metrics) listening on :%s", httpPort)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve http: %v", err)
		}
	}()

	// 9. Sidecar transparent proxy — separate port, this is what agent
	// outbound traffic is actually routed through.
	proxyPort := os.Getenv("PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "8888"
	}
	proxy := gateway.NewProxy(enforcer)
	proxyLis, proxySrv, err := proxy.NewListener(fmt.Sprintf(":%s", proxyPort))
	if err != nil {
		log.Fatalf("failed to start sidecar proxy: %v", err)
	}
	go func() {
		log.Printf("gateway sidecar proxy listening on :%s", proxyPort)
		if err := proxySrv.Serve(proxyLis); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve proxy: %v", err)
		}
	}()

	// Wait for interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("shutting down gracefully...")
	bgCancel()
	grpcServer.GracefulStop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpSrv.Shutdown(shutdownCtx)
	proxySrv.Shutdown(shutdownCtx)
}

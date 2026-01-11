package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/banking/user-service/internal/api/http/handlers"
	apihttp "github.com/banking/user-service/internal/api/http"
	"github.com/banking/user-service/internal/config"
	"github.com/banking/user-service/internal/crypto"
	"github.com/banking/user-service/internal/events"
	"github.com/banking/user-service/internal/pkg/health"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/pkg/tracer"
	"github.com/banking/user-service/internal/repository/postgres"
	rediscache "github.com/banking/user-service/internal/repository/redis"
	"github.com/banking/user-service/internal/resilience"
	"github.com/banking/user-service/internal/service"
)

// Version is set at build time
var Version = "dev"

func main() {
	// Handle health check flag
	if len(os.Args) > 1 && os.Args[1] == "-health-check" {
		if err := healthCheck(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	log, err := logger.New(logger.Config{
		Level:           cfg.Logging.Level,
		Format:          cfg.Logging.Format,
		OutputPath:      cfg.Logging.OutputPath,
		EnablePIIMask:   cfg.Logging.EnablePIIMask,
		EnableRequestID: cfg.Logging.EnableRequestID,
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer log.Sync()

	log.Info("Starting user-service",
		logger.Component("main"),
		logger.Operation("startup"),
	)

	// Initialize tracer
	tr, err := tracer.New(ctx, tracer.Config{
		Enabled:      cfg.Tracing.Enabled,
		ServiceName:  cfg.Tracing.ServiceName,
		OTLPEndpoint: cfg.Tracing.OTLPEndpoint,
		SampleRate:   cfg.Tracing.SampleRate,
		Version:      Version,
	})
	if err != nil {
		log.Warn("failed to create tracer, continuing without tracing", logger.ErrorField(err))
	} else {
		defer tr.Shutdown(ctx)
	}

	// Initialize circuit breakers
	circuitBreakers := resilience.NewCircuitBreakers()

	// Initialize PostgreSQL connection pool
	pgPool, err := initPostgres(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer pgPool.Close()

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Addr(),
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
	})
	defer redisClient.Close()

	// Initialize encryption
	encryptor, err := crypto.NewFieldEncryptor(
		cfg.Encryption.EncryptionKeysBase64,
		cfg.Encryption.CurrentKeyVersion,
		cfg.Encryption.AuditHMACSecret,
	)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Initialize health checker
	healthChecker := health.New(5 * time.Second)
	healthChecker.Register("postgres", health.PostgresChecker(func(ctx context.Context) error {
		return pgPool.Ping(ctx)
	}))
	healthChecker.Register("redis", health.RedisChecker(func(ctx context.Context) error {
		return redisClient.Ping(ctx).Err()
	}))

	// Initialize repositories
	userRepo := postgres.NewUserRepository(pgPool, encryptor, circuitBreakers.Postgres)
	userCache := rediscache.NewUserCache(redisClient, circuitBreakers.Redis, cfg.Redis.DefaultTTL)

	// Initialize Kafka audit producer
	auditProducer, err := events.NewAuditProducer(events.AuditProducerConfig{
		Brokers:          cfg.Kafka.Brokers,
		Topic:            cfg.Kafka.AuditTopic,
		BufferSize:       1000,
		RequireAcks:      -1, // WaitForAll
		EnableIdempotent: cfg.Kafka.EnableIdempotent,
	}, circuitBreakers.Kafka, nil, log)
	if err != nil {
		log.Warn("failed to create audit producer, audit events will be buffered", logger.ErrorField(err))
	} else {
		defer auditProducer.Close()
	}

	// Initialize services
	userService := service.NewUserService(
		userRepo,
		userCache,
		auditProducer,
		log,
		[]byte(cfg.Encryption.AuditHMACSecret),
	)

	// Load JWT public key
	authPublicKey, err := loadPublicKey(cfg.Auth.JWTPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load JWT public key: %w", err)
	}

	// Initialize HTTP router
	router := apihttp.NewRouter(apihttp.RouterDeps{
		Config:         cfg,
		Logger:         log,
		Health:         healthChecker,
		UserService:    userService,
		AddressService: nil, // TODO: Initialize
		DeviceService:  nil, // TODO: Initialize  
		PrefService:    nil, // TODO: Initialize
		RedisClient:    redisClient,
		CircuitBreaker: circuitBreakers.Redis,
		AuthPublicKey:  authPublicKey,
	})

	// Start server in goroutine
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	go func() {
		log.Info("HTTP server starting", logger.Component("http"))
		if err := router.StartWithAddr(serverAddr); err != nil && err != http.ErrServerClosed {
			log.Fatal("HTTP server failed", logger.ErrorField(err))
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := router.Shutdown(shutdownCtx); err != nil {
		log.Error("Server forced to shutdown", logger.ErrorField(err))
		return err
	}

	log.Info("Server exited gracefully")
	return nil
}

func initPostgres(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.DSN())
	if err != nil {
		return nil, err
	}

	poolConfig.MaxConns = int32(cfg.Database.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.Database.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.Database.ConnMaxLifetime
	poolConfig.MaxConnIdleTime = cfg.Database.ConnMaxIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

func healthCheck() error {
	resp, err := http.Get("http://localhost:8080/health/live")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}

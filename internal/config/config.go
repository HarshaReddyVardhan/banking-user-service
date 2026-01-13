package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the service
type Config struct {
	Server     ServerConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	MongoDB    MongoDBConfig
	Kafka      KafkaConfig
	Encryption EncryptionConfig
	Auth       AuthConfig
	RateLimit  RateLimitConfig
	Tracing    TracingConfig
	Logging    LoggingConfig
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	ReadTimeout        time.Duration `mapstructure:"read_timeout"`
	WriteTimeout       time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout    time.Duration `mapstructure:"shutdown_timeout"`
	CORSAllowedOrigins []string      `mapstructure:"cors_allowed_origins"` // SECURITY: Empty = no CORS, explicit origins only
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	Database           string        `mapstructure:"database"`
	Username           string        `mapstructure:"username"`
	Password           string        `mapstructure:"password"`
	SSLMode            string        `mapstructure:"ssl_mode"`
	MaxOpenConns       int           `mapstructure:"max_open_conns"`
	MaxIdleConns       int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime    time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime    time.Duration `mapstructure:"conn_max_idle_time"`
	CircuitBreakerName string        `mapstructure:"circuit_breaker_name"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	Password           string        `mapstructure:"password"`
	DB                 int           `mapstructure:"db"`
	PoolSize           int           `mapstructure:"pool_size"`
	MinIdleConns       int           `mapstructure:"min_idle_conns"`
	DefaultTTL         time.Duration `mapstructure:"default_ttl"`
	CircuitBreakerName string        `mapstructure:"circuit_breaker_name"`
}

// MongoDBConfig holds MongoDB configuration
type MongoDBConfig struct {
	URI                string        `mapstructure:"uri"`
	Database           string        `mapstructure:"database"`
	ConnectTimeout     time.Duration `mapstructure:"connect_timeout"`
	MaxPoolSize        uint64        `mapstructure:"max_pool_size"`
	CircuitBreakerName string        `mapstructure:"circuit_breaker_name"`
}

// KafkaConfig holds Kafka configuration
type KafkaConfig struct {
	Brokers            []string `mapstructure:"brokers"`
	AuditTopic         string   `mapstructure:"audit_topic"`
	EventTopic         string   `mapstructure:"event_topic"`
	ConsumerGroup      string   `mapstructure:"consumer_group"`
	RequiredAcks       int      `mapstructure:"required_acks"`
	EnableIdempotent   bool     `mapstructure:"enable_idempotent"`
	CircuitBreakerName string   `mapstructure:"circuit_breaker_name"`
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	CurrentKeyVersion    int           `mapstructure:"current_key_version"`
	KeyRotationDays      int           `mapstructure:"key_rotation_days"`
	VaultEnabled         bool          `mapstructure:"vault_enabled"`
	VaultAddress         string        `mapstructure:"vault_address"`
	VaultKeyPath         string        `mapstructure:"vault_key_path"`
	AuditHMACSecret      string        `mapstructure:"audit_hmac_secret"`
	EncryptionKeysBase64 []string      `mapstructure:"encryption_keys"` // For non-Vault env
	KeyCheckInterval     time.Duration `mapstructure:"key_check_interval"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	JWTPublicKeyPath string   `mapstructure:"jwt_public_key_path"`
	JWTIssuer        string   `mapstructure:"jwt_issuer"`
	JWTAudience      []string `mapstructure:"jwt_audience"`
	ServiceMTLSCert  string   `mapstructure:"service_mtls_cert"`
	ServiceMTLSKey   string   `mapstructure:"service_mtls_key"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	PerUserPerMinute       int  `mapstructure:"per_user_per_minute"`
	PerIPPerMinute         int  `mapstructure:"per_ip_per_minute"`
	ProfileUpdatesPerHour  int  `mapstructure:"profile_updates_per_hour"`
	AddressChangesPerHour  int  `mapstructure:"address_changes_per_hour"`
	BurstSize              int  `mapstructure:"burst_size"`
	EnableInMemoryFallback bool `mapstructure:"enable_inmemory_fallback"`
}

// TracingConfig holds OpenTelemetry tracing settings
type TracingConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	ServiceName  string  `mapstructure:"service_name"`
	OTLPEndpoint string  `mapstructure:"otlp_endpoint"`
	SampleRate   float64 `mapstructure:"sample_rate"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level           string `mapstructure:"level"`
	Format          string `mapstructure:"format"` // json or console
	OutputPath      string `mapstructure:"output_path"`
	EnablePIIMask   bool   `mapstructure:"enable_pii_mask"`
	EnableRequestID bool   `mapstructure:"enable_request_id"`
}

// Load loads configuration from environment and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Read from environment variables
	v.SetEnvPrefix("USER_SERVICE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Optionally read from config file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/user-service/")
	v.AddConfigPath("./configs/")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we use env vars
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.shutdown_timeout", 15*time.Second)

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.database", "user_service")
	v.SetDefault("database.ssl_mode", "require")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)
	v.SetDefault("database.conn_max_idle_time", 1*time.Minute)
	v.SetDefault("database.circuit_breaker_name", "postgres")

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 2)
	v.SetDefault("redis.default_ttl", 5*time.Minute)
	v.SetDefault("redis.circuit_breaker_name", "redis")

	// MongoDB defaults
	v.SetDefault("mongodb.database", "user_preferences")
	v.SetDefault("mongodb.connect_timeout", 10*time.Second)
	v.SetDefault("mongodb.max_pool_size", 50)
	v.SetDefault("mongodb.circuit_breaker_name", "mongodb")

	// Kafka defaults
	v.SetDefault("kafka.audit_topic", "user-audit-events")
	v.SetDefault("kafka.event_topic", "user-events")
	v.SetDefault("kafka.consumer_group", "user-service")
	v.SetDefault("kafka.required_acks", -1) // WaitForAll
	v.SetDefault("kafka.enable_idempotent", true)
	v.SetDefault("kafka.circuit_breaker_name", "kafka")

	// Encryption defaults
	v.SetDefault("encryption.current_key_version", 1)
	v.SetDefault("encryption.key_rotation_days", 90)
	v.SetDefault("encryption.vault_enabled", false)
	v.SetDefault("encryption.key_check_interval", 1*time.Hour)

	// Rate limit defaults
	v.SetDefault("ratelimit.per_user_per_minute", 100)
	v.SetDefault("ratelimit.per_ip_per_minute", 50)
	v.SetDefault("ratelimit.profile_updates_per_hour", 10)
	v.SetDefault("ratelimit.address_changes_per_hour", 20)
	v.SetDefault("ratelimit.burst_size", 10)
	v.SetDefault("ratelimit.enable_inmemory_fallback", true)

	// Tracing defaults
	v.SetDefault("tracing.enabled", true)
	v.SetDefault("tracing.service_name", "user-service")
	v.SetDefault("tracing.sample_rate", 0.1)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output_path", "stdout")
	v.SetDefault("logging.enable_pii_mask", true)
	v.SetDefault("logging.enable_request_id", true)
}

func validate(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	if cfg.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	// SECURITY: Require SSL for database connections
	if cfg.Database.SSLMode == "" || cfg.Database.SSLMode == "disable" {
		return fmt.Errorf("database SSL mode must be enabled (require, verify-ca, or verify-full)")
	}

	if cfg.Encryption.VaultEnabled && cfg.Encryption.VaultAddress == "" {
		return fmt.Errorf("vault address is required when vault is enabled")
	}

	if !cfg.Encryption.VaultEnabled && len(cfg.Encryption.EncryptionKeysBase64) == 0 {
		return fmt.Errorf("encryption keys are required when vault is disabled")
	}

	if cfg.Encryption.AuditHMACSecret == "" {
		return fmt.Errorf("audit HMAC secret is required")
	}

	// SECURITY: Enforce minimum HMAC secret length for cryptographic security
	if len(cfg.Encryption.AuditHMACSecret) < 32 {
		return fmt.Errorf("audit HMAC secret must be at least 32 characters for security")
	}

	// SECURITY: Validate rate limits are reasonable
	if cfg.RateLimit.PerUserPerMinute <= 0 {
		return fmt.Errorf("per_user_per_minute rate limit must be positive")
	}
	if cfg.RateLimit.PerIPPerMinute <= 0 {
		return fmt.Errorf("per_ip_per_minute rate limit must be positive")
	}
	// SECURITY: Cap rate limits to prevent abuse if misconfigured
	if cfg.RateLimit.PerUserPerMinute > 10000 {
		return fmt.Errorf("per_user_per_minute rate limit too high (max 10000)")
	}
	if cfg.RateLimit.PerIPPerMinute > 1000 {
		return fmt.Errorf("per_ip_per_minute rate limit too high (max 1000)")
	}

	// SECURITY: Validate key rotation period (PCI-DSS requires rotation at least annually)
	if cfg.Encryption.KeyRotationDays > 365 {
		return fmt.Errorf("key rotation period exceeds 365 days, violates security best practices")
	}

	return nil
}

// DSN returns the PostgreSQL connection string
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.Host, c.Port, c.Database, c.Username, c.Password, c.SSLMode,
	)
}

// RedisAddr returns the Redis address
func (c *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetCORSAllowedOrigins returns the configured CORS allowed origins
// SECURITY: Returns empty slice if not configured (no CORS allowed - most secure default)
func (c *Config) GetCORSAllowedOrigins() []string {
	if len(c.Server.CORSAllowedOrigins) == 0 {
		return []string{} // Empty = no cross-origin requests allowed
	}
	return c.Server.CORSAllowedOrigins
}

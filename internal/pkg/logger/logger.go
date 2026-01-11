package logger

import (
	"context"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// RequestIDKey is the context key for request ID
	RequestIDKey ContextKey = "request_id"
	// UserIDKey is the context key for user ID
	UserIDKey ContextKey = "user_id"
	// ServiceKey is the context key for calling service
	ServiceKey ContextKey = "service"
)

// Logger wraps zap.Logger with PII sanitization
type Logger struct {
	*zap.Logger
	enablePIIMask   bool
	enableRequestID bool
}

// PII patterns for sanitization
var (
	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	phonePattern = regexp.MustCompile(`\+?[1-9]\d{1,14}`)
	// Match common name patterns (capitalized words)
	namePattern = regexp.MustCompile(`\b[A-Z][a-z]+\s+[A-Z][a-z]+\b`)
)

// Config for logger initialization
type Config struct {
	Level           string
	Format          string // "json" or "console"
	OutputPath      string
	EnablePIIMask   bool
	EnableRequestID bool
}

// New creates a new PII-safe logger
func New(cfg Config) (*Logger, error) {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	var zapCfg zap.Config
	if cfg.Format == "console" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}

	zapCfg.Level = zap.NewAtomicLevelAt(level)

	if cfg.OutputPath != "" && cfg.OutputPath != "stdout" {
		zapCfg.OutputPaths = []string{cfg.OutputPath}
	}

	// Add caller and stacktrace for errors
	zapCfg.EncoderConfig.TimeKey = "timestamp"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapCfg.EncoderConfig.CallerKey = "caller"
	zapCfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	zapLogger, err := zapCfg.Build(
		zap.AddCallerSkip(1), // Skip the wrapper
	)
	if err != nil {
		return nil, err
	}

	return &Logger{
		Logger:          zapLogger,
		enablePIIMask:   cfg.EnablePIIMask,
		enableRequestID: cfg.EnableRequestID,
	}, nil
}

// WithContext creates a logger with request context fields
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := []zap.Field{}

	if l.enableRequestID {
		if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
			fields = append(fields, zap.String("request_id", requestID))
		}
	}

	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		// User ID is safe to log as-is (it's a UUID)
		fields = append(fields, zap.String("user_id", userID))
	}

	if service, ok := ctx.Value(ServiceKey).(string); ok && service != "" {
		fields = append(fields, zap.String("calling_service", service))
	}

	return &Logger{
		Logger:          l.Logger.With(fields...),
		enablePIIMask:   l.enablePIIMask,
		enableRequestID: l.enableRequestID,
	}
}

// SanitizeString removes PII from a string
func (l *Logger) SanitizeString(s string) string {
	if !l.enablePIIMask {
		return s
	}
	return sanitizePII(s)
}

// sanitizePII masks all PII patterns in a string
func sanitizePII(s string) string {
	// Mask emails: john.doe@example.com -> j***@e***.com
	s = emailPattern.ReplaceAllStringFunc(s, maskEmail)

	// Mask phone numbers: +14155551234 -> +1***1234
	s = phonePattern.ReplaceAllStringFunc(s, maskPhone)

	return s
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***@***.***"
	}
	local := parts[0]
	domain := parts[1]

	maskedLocal := string(local[0]) + "***"
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return maskedLocal + "@***.***"
	}
	maskedDomain := string(domainParts[0][0]) + "***." + domainParts[len(domainParts)-1]

	return maskedLocal + "@" + maskedDomain
}

func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	// Keep first 2 and last 4 characters
	prefix := phone[:2]
	suffix := phone[len(phone)-4:]
	return prefix + "***" + suffix
}

// Info logs an info message with PII sanitization
func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.Logger.Info(l.SanitizeString(msg), l.sanitizeFields(fields)...)
}

// Error logs an error message with PII sanitization
func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.Logger.Error(l.SanitizeString(msg), l.sanitizeFields(fields)...)
}

// Warn logs a warning message with PII sanitization
func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.Logger.Warn(l.SanitizeString(msg), l.sanitizeFields(fields)...)
}

// Debug logs a debug message with PII sanitization
func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.Logger.Debug(l.SanitizeString(msg), l.sanitizeFields(fields)...)
}

// Fatal logs a fatal message with PII sanitization and exits
func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.Logger.Fatal(l.SanitizeString(msg), l.sanitizeFields(fields)...)
}

// sanitizeFields sanitizes string fields for PII
func (l *Logger) sanitizeFields(fields []zap.Field) []zap.Field {
	if !l.enablePIIMask {
		return fields
	}

	sanitized := make([]zap.Field, len(fields))
	for i, f := range fields {
		sanitized[i] = l.sanitizeField(f)
	}
	return sanitized
}

func (l *Logger) sanitizeField(f zap.Field) zap.Field {
	// Only sanitize string fields with PII-sensitive names
	piiFields := map[string]bool{
		"email":      true,
		"phone":      true,
		"name":       true,
		"legal_name": true,
		"address":    true,
		"ip":         true,
		"ip_address": true,
	}

	if f.Type == zapcore.StringType && piiFields[f.Key] {
		return zap.String(f.Key, sanitizePII(f.String))
	}

	return f
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Named returns a named child logger
func (l *Logger) Named(name string) *Logger {
	return &Logger{
		Logger:          l.Logger.Named(name),
		enablePIIMask:   l.enablePIIMask,
		enableRequestID: l.enableRequestID,
	}
}

// With creates a child logger with additional fields
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{
		Logger:          l.Logger.With(l.sanitizeFields(fields)...),
		enablePIIMask:   l.enablePIIMask,
		enableRequestID: l.enableRequestID,
	}
}

// Default fields for structured logging
func RequestID(id string) zap.Field {
	return zap.String("request_id", id)
}

func UserID(id string) zap.Field {
	return zap.String("user_id", id)
}

func Component(name string) zap.Field {
	return zap.String("component", name)
}

func Operation(name string) zap.Field {
	return zap.String("operation", name)
}

func Duration(d int64) zap.Field {
	return zap.Int64("duration_ms", d)
}

func HTTPStatus(status int) zap.Field {
	return zap.Int("http_status", status)
}

func ErrorField(err error) zap.Field {
	if err == nil {
		return zap.Skip()
	}
	return zap.Error(err)
}

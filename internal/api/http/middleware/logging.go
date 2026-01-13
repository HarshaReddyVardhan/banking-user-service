package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime/debug"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/banking/user-service/internal/pkg/logger"
)

// Logging middleware for structured request/response logging with PII safety
func Logging(log *logger.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			req := c.Request()

			// Get request ID
			requestID := GetRequestIDFromEcho(c)

			// Process request
			err := next(c)

			// Calculate duration
			duration := time.Since(start)

			// Get response status
			status := c.Response().Status
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					status = he.Code
				}
			}

			// SECURITY: Hash IP address for privacy (GDPR compliance)
			hashedIP := hashIPForLogging(c.RealIP())

			// Build log fields - PII-SAFE
			fields := []zap.Field{
				zap.String("request_id", requestID),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
				zap.Int("status", status),
				zap.Int64("duration_ms", duration.Milliseconds()),
				zap.String("remote_ip_hash", hashedIP), // SECURITY: Hashed IP, not raw
				zap.String("user_agent", req.UserAgent()),
				zap.Int64("bytes_in", req.ContentLength),
				zap.Int64("bytes_out", c.Response().Size),
			}

			// Add user ID if authenticated (UUIDs are not PII)
			if userID, ok := GetUserIDFromEcho(c); ok {
				fields = append(fields, zap.String("user_id", userID.String()))
			}

			// Add error if present
			if err != nil {
				fields = append(fields, zap.Error(err))
			}

			// Log based on status
			if status >= 500 {
				log.Error("request failed", fields...)
			} else if status >= 400 {
				log.Warn("request error", fields...)
			} else {
				log.Info("request completed", fields...)
			}

			return err
		}
	}
}

// hashIPForLogging creates a privacy-preserving hash of an IP address
// SECURITY: This is for logging only - use full IP for security operations like rate limiting
func hashIPForLogging(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip))
	hash := h.Sum(nil)
	// Return first 16 chars for readability while maintaining anonymity
	return hex.EncodeToString(hash)[:16]
}

// RecoveryLogging handles panics and logs them with stack traces
func RecoveryLogging(log *logger.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					requestID := GetRequestIDFromEcho(c)

					// SECURITY: Capture stack trace for debugging but never expose to client
					stack := string(debug.Stack())

					log.Error("panic recovered",
						zap.String("request_id", requestID),
						zap.Any("panic", r),
						zap.String("path", c.Request().URL.Path),
						zap.String("method", c.Request().Method),
						zap.String("stack_trace", stack), // For debugging - never expose to client
					)

					// Return 500 error without exposing internal details
					c.Error(echo.NewHTTPError(500, "internal server error"))
				}
			}()
			return next(c)
		}
	}
}

package middleware

import (
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

			// Build log fields - PII-SAFE
			fields := []zap.Field{
				zap.String("request_id", requestID),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
				zap.Int("status", status),
				zap.Int64("duration_ms", duration.Milliseconds()),
				zap.String("remote_ip", c.RealIP()), // Consider hashing in production
				zap.String("user_agent", req.UserAgent()),
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

// RecoveryLogging handles panics and logs them
func RecoveryLogging(log *logger.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					requestID := GetRequestIDFromEcho(c)
					log.Error("panic recovered",
						zap.String("request_id", requestID),
						zap.Any("panic", r),
						zap.String("path", c.Request().URL.Path),
					)
					
					// Return 500 error
					c.Error(echo.NewHTTPError(500, "internal server error"))
				}
			}()
			return next(c)
		}
	}
}

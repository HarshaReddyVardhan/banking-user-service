package middleware

import (
	"context"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// ContextKey type for context keys
type ContextKey string

const (
	// RequestIDKey is the context key for request ID
	RequestIDKey ContextKey = "request_id"
	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
)

// RequestID middleware generates or extracts request IDs for tracing
// SECURITY: Validates incoming request IDs to prevent injection attacks
func RequestID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Try to get request ID from header (from API gateway)
			requestID := c.Request().Header.Get(RequestIDHeader)

			// SECURITY: Validate request ID format to prevent log injection
			// Only accept valid UUIDs or generate a new one
			if requestID != "" {
				if !isValidRequestID(requestID) {
					// Invalid format - generate new ID instead of using potentially malicious value
					requestID = uuid.New().String()
				}
			} else {
				// Generate new ID if not provided
				requestID = uuid.New().String()
			}

			// Set in response header
			c.Response().Header().Set(RequestIDHeader, requestID)

			// Set in context
			ctx := context.WithValue(c.Request().Context(), RequestIDKey, requestID)
			c.SetRequest(c.Request().WithContext(ctx))

			// Also set in Echo context for easy access
			c.Set(string(RequestIDKey), requestID)

			return next(c)
		}
	}
}

// isValidRequestID validates the format of a request ID
// Accepts UUID format (with or without hyphens) and limits length
func isValidRequestID(id string) bool {
	// SECURITY: Reject excessively long IDs that could be injection attempts
	if len(id) > 64 {
		return false
	}

	// Reject IDs with potentially dangerous characters
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}

	// Try to parse as UUID (most common case)
	if _, err := uuid.Parse(id); err == nil {
		return true
	}

	// Allow alphanumeric IDs up to 64 chars for compatibility with other tracing systems
	return len(id) >= 16 && len(id) <= 64
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// GetRequestIDFromEcho extracts request ID from Echo context
func GetRequestIDFromEcho(c echo.Context) string {
	if id, ok := c.Get(string(RequestIDKey)).(string); ok {
		return id
	}
	return ""
}

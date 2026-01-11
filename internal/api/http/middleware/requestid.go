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
func RequestID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Try to get request ID from header (from API gateway)
			requestID := c.Request().Header.Get(RequestIDHeader)
			
			// Generate new ID if not provided
			if requestID == "" {
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

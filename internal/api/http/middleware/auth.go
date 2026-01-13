package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Context keys for auth
const (
	UserIDKey      ContextKey = "user_id"
	SubjectKey     ContextKey = "subject"
	ScopesKey      ContextKey = "scopes"
	ServiceNameKey ContextKey = "service_name"
)

// Common errors
var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidToken   = errors.New("invalid token")
	ErrTokenExpired   = errors.New("token expired")
	ErrMissingAuth    = errors.New("missing authorization header")
	ErrInvalidSubject = errors.New("invalid subject in token")
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	PublicKey interface{} // RSA or ECDSA public key
	Issuer    string
	Audiences []string
	SkipPaths []string // Paths to skip auth (e.g., health checks)
}

// Claims represents JWT claims
type Claims struct {
	jwt.RegisteredClaims
	Scopes      []string `json:"scopes,omitempty"`
	ServiceName string   `json:"service_name,omitempty"` // For service-to-service
}

// Auth middleware validates JWT tokens and extracts user identity
func Auth(cfg AuthConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip auth for certain paths
			path := c.Path()
			for _, skip := range cfg.SkipPaths {
				if strings.HasPrefix(path, skip) {
					return next(c)
				}
			}

			// Extract token from Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, ErrMissingAuth.Error())
			}

			// Expect "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, ErrInvalidToken.Error())
			}
			tokenString := parts[1]

			// Parse and validate token
			claims, err := validateToken(tokenString, cfg)
			if err != nil {
				if errors.Is(err, jwt.ErrTokenExpired) {
					return echo.NewHTTPError(http.StatusUnauthorized, ErrTokenExpired.Error())
				}
				return echo.NewHTTPError(http.StatusUnauthorized, ErrInvalidToken.Error())
			}

			// Extract subject (user ID)
			subject := claims.Subject
			if subject == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, ErrInvalidSubject.Error())
			}

			// Parse subject as UUID
			userID, err := uuid.Parse(subject)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, ErrInvalidSubject.Error())
			}

			// Set in context
			ctx := c.Request().Context()
			ctx = context.WithValue(ctx, UserIDKey, userID)
			ctx = context.WithValue(ctx, SubjectKey, subject)
			ctx = context.WithValue(ctx, ScopesKey, claims.Scopes)
			if claims.ServiceName != "" {
				ctx = context.WithValue(ctx, ServiceNameKey, claims.ServiceName)
			}
			c.SetRequest(c.Request().WithContext(ctx))

			// Also set in Echo context
			c.Set(string(UserIDKey), userID)
			c.Set(string(SubjectKey), subject)
			c.Set(string(ScopesKey), claims.Scopes)

			return next(c)
		}
	}
}

func validateToken(tokenString string, cfg AuthConfig) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// SECURITY: Validate signing method to prevent algorithm confusion attacks (CVE-2015-2951)
		// Only accept RSA or ECDSA - never accept HS* with public key
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			// RSA is acceptable
		case *jwt.SigningMethodRSAPSS:
			// RSA-PSS is acceptable
		case *jwt.SigningMethodECDSA:
			// ECDSA is acceptable
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate issuer
	if cfg.Issuer != "" && claims.Issuer != cfg.Issuer {
		return nil, errors.New("invalid issuer")
	}

	// Validate audience
	if len(cfg.Audiences) > 0 {
		found := false
		for _, aud := range claims.Audience {
			for _, expected := range cfg.Audiences {
				if aud == expected {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, errors.New("invalid audience")
		}
	}

	return claims, nil
}

// RequireOwnership middleware ensures the authenticated user can only access their own resources
// This prevents IDOR (Insecure Direct Object Reference) attacks
func RequireOwnership(paramName string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get authenticated user ID from context
			authUserID, ok := c.Get(string(UserIDKey)).(uuid.UUID)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, ErrUnauthorized.Error())
			}

			// For /me endpoints, the user ID is implicit
			resourceUserID := c.Param(paramName)
			if resourceUserID == "" || resourceUserID == "me" {
				// User is accessing their own resource
				return next(c)
			}

			// Parse resource user ID
			parsedResourceID, err := uuid.Parse(resourceUserID)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid user ID format")
			}

			// Check ownership
			if authUserID != parsedResourceID {
				// Log potential IDOR attempt
				return echo.NewHTTPError(http.StatusForbidden, ErrForbidden.Error())
			}

			return next(c)
		}
	}
}

// RequireScopes middleware checks if the token has required scopes
func RequireScopes(requiredScopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			scopes, ok := c.Get(string(ScopesKey)).([]string)
			if !ok {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			// Check if all required scopes are present
			scopeMap := make(map[string]bool)
			for _, s := range scopes {
				scopeMap[s] = true
			}

			for _, required := range requiredScopes {
				if !scopeMap[required] {
					return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
				}
			}

			return next(c)
		}
	}
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return id, ok
}

// GetUserIDFromEcho extracts user ID from Echo context
func GetUserIDFromEcho(c echo.Context) (uuid.UUID, bool) {
	id, ok := c.Get(string(UserIDKey)).(uuid.UUID)
	return id, ok
}

// IsServiceCall checks if the request is from an internal service
func IsServiceCall(ctx context.Context) bool {
	_, ok := ctx.Value(ServiceNameKey).(string)
	return ok
}

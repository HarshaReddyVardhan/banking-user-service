package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Helper to create test ECDSA keys
func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// Helper to create a signed JWT
func createTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims *Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestAuth_ValidToken(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	userID := uuid.New()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "test-issuer",
			Audience:  []string{"user-service"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Scopes: []string{"user:read", "user:write"},
	}
	tokenString := createTestToken(t, privateKey, claims)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
		Issuer:    "test-issuer",
		Audiences: []string{"user-service"},
	}

	handler := Auth(config)(func(c echo.Context) error {
		// Verify user ID was set
		gotUserID, ok := GetUserIDFromEcho(c)
		if !ok {
			t.Error("user ID not found in context")
		}
		if gotUserID != userID {
			t.Errorf("expected user ID %s, got %s", userID, gotUserID)
		}
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestAuth_MissingHeader(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	// No Authorization header
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
		Issuer:    "test-issuer",
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for missing header")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got: %v", err)
	}
}

func TestAuth_InvalidBearerFormat(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	testCases := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "token123"},
		{"wrong prefix", "Basic token123"},
		{"empty token", "Bearer "},
		{"bearer lowercase", "bearer token123"}, // should still work
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
			req.Header.Set("Authorization", tc.header)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			config := AuthConfig{
				PublicKey: publicKey,
			}

			handler := Auth(config)(func(c echo.Context) error {
				return c.String(http.StatusOK, "ok")
			})

			err := handler(c)
			// Most should fail, but "bearer" lowercase should potentially work at parse level
			// (still fails at token validation)
			if tc.name != "bearer lowercase" && err == nil {
				t.Error("expected error for invalid bearer format")
			}
		})
	}
}

func TestAuth_ExpiredToken(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	userID := uuid.New()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	tokenString := createTestToken(t, privateKey, claims)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for expired token")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got: %v", err)
	}
}

func TestAuth_InvalidIssuer(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	userID := uuid.New()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "wrong-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tokenString := createTestToken(t, privateKey, claims)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
		Issuer:    "expected-issuer",
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for invalid issuer")
	}
}

func TestAuth_InvalidAudience(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	userID := uuid.New()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Audience:  []string{"wrong-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tokenString := createTestToken(t, privateKey, claims)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
		Audiences: []string{"user-service"},
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for invalid audience")
	}
}

func TestAuth_AlgorithmConfusion(t *testing.T) {
	// Security test: Ensure HMAC signing with public key is rejected
	// This prevents CVE-2015-2951 algorithm confusion attack
	_, publicKey := generateTestKeyPair(t)
	userID := uuid.New()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Try to create a token signed with HMAC using a fake key
	// In a real attack, they would use the public key bytes as HMAC secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("fake-hmac-secret"))

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("algorithm confusion attack should be prevented")
	}
}

func TestAuth_InvalidSubject(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "not-a-uuid",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tokenString := createTestToken(t, privateKey, claims)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config := AuthConfig{
		PublicKey: publicKey,
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for invalid UUID subject")
	}
}

func TestAuth_SkipPaths(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	// No Authorization header
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/health/ready")

	config := AuthConfig{
		PublicKey: publicKey,
		SkipPaths: []string{"/health"},
	}

	handler := Auth(config)(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Errorf("health check should skip auth, got: %v", err)
	}
}

func TestRequireScopes_Success(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set scopes in context
	c.Set(string(ScopesKey), []string{"user:read", "user:write", "admin"})

	handler := RequireScopes("user:read", "user:write")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestRequireScopes_MissingScope(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(string(ScopesKey), []string{"user:read"})

	handler := RequireScopes("user:read", "user:write")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for missing scope")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got: %v", err)
	}
}

func TestRequireScopes_NoScopes(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// No scopes set in context

	handler := RequireScopes("user:read")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error when no scopes")
	}
}

func TestRequireOwnership_MeEndpoint(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	userID := uuid.New()
	c.Set(string(UserIDKey), userID)
	c.SetParamNames("id")
	c.SetParamValues("me")

	handler := RequireOwnership("id")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Errorf("expected no error for /me endpoint, got: %v", err)
	}
}

func TestRequireOwnership_SameUser(t *testing.T) {
	e := echo.New()
	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/users/"+userID.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(string(UserIDKey), userID)
	c.SetParamNames("id")
	c.SetParamValues(userID.String())

	handler := RequireOwnership("id")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err != nil {
		t.Errorf("expected no error for same user, got: %v", err)
	}
}

func TestRequireOwnership_DifferentUser(t *testing.T) {
	e := echo.New()
	authUserID := uuid.New()
	resourceUserID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/users/"+resourceUserID.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Set(string(UserIDKey), authUserID)
	c.SetParamNames("id")
	c.SetParamValues(resourceUserID.String())

	handler := RequireOwnership("id")(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	err := handler(c)
	if err == nil {
		t.Error("expected error for IDOR attempt")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got: %v", err)
	}
}

func TestGetUserID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	userID := uuid.New()
	c.Set(string(UserIDKey), userID)

	gotID, ok := GetUserIDFromEcho(c)
	if !ok {
		t.Error("expected to find user ID")
	}
	if gotID != userID {
		t.Errorf("expected %s, got %s", userID, gotID)
	}
}

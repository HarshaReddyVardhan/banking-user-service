package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	// Create rate limiter without Redis (uses in-memory fallback)
	limiter := NewRateLimiter(nil, nil, RateLimitConfig{
		PerUserPerMinute:       100,
		PerIPPerMinute:         50,
		ProfileUpdatesPerHour:  10,
		AddressChangesPerHour:  20,
		BurstSize:              10,
		EnableInMemoryFallback: true,
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := limiter.RateLimit()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Should succeed within limit
	err := handler(c)
	if err != nil {
		t.Errorf("expected request to succeed, got: %v", err)
	}

	// Check rate limit headers
	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("expected X-RateLimit-Limit header")
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("expected X-RateLimit-Reset header")
	}
}

func TestRateLimit_BlocksAfterLimit(t *testing.T) {
	limiter := NewRateLimiter(nil, nil, RateLimitConfig{
		PerUserPerMinute:       3, // Very low limit for testing
		PerIPPerMinute:         3,
		EnableInMemoryFallback: true,
	})

	e := echo.New()

	handler := limiter.RateLimit()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Make requests up to the limit
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		if err != nil {
			t.Errorf("request %d should succeed, got: %v", i+1, err)
		}
	}

	// Next request should be blocked
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	if err == nil {
		t.Error("expected rate limit error")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got: %v", err)
	}

	// Check Retry-After header
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestRateLimit_PerUserLimit(t *testing.T) {
	limiter := NewRateLimiter(nil, nil, RateLimitConfig{
		PerUserPerMinute:       5,
		PerIPPerMinute:         3,
		EnableInMemoryFallback: true,
	})

	e := echo.New()
	userID := uuid.New()

	handler := limiter.RateLimit()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Authenticated requests should use per-user limit (higher)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(string(UserIDKey), userID)

		err := handler(c)
		if err != nil {
			t.Errorf("authenticated request %d should succeed (within per-user limit), got: %v", i+1, err)
		}
	}
}

func TestRateLimit_DifferentIPs(t *testing.T) {
	limiter := NewRateLimiter(nil, nil, RateLimitConfig{
		PerIPPerMinute:         2,
		EnableInMemoryFallback: true,
	})

	e := echo.New()

	handler := limiter.RateLimit()(func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Different IPs should have separate limits
	ips := []string{"192.168.1.1:1234", "192.168.1.2:1234", "192.168.1.3:1234"}

	for _, ip := range ips {
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = ip
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler(c)
			if err != nil {
				t.Errorf("request from %s should succeed, got: %v", ip, err)
			}
		}
	}
}

func TestInMemoryLimiter_Check(t *testing.T) {
	limiter := newInMemoryLimiter()
	defer limiter.Stop()

	key := "test:key"
	limit := 5
	window := time.Minute

	// First request
	allowed, remaining, _, _ := limiter.check(key, limit, window)
	if !allowed {
		t.Error("first request should be allowed")
	}
	if remaining != 4 {
		t.Errorf("expected remaining 4, got %d", remaining)
	}

	// More requests
	for i := 0; i < 4; i++ {
		allowed, _, _, _ = limiter.check(key, limit, window)
		if !allowed {
			t.Error("request within limit should be allowed")
		}
	}

	// Next request should be blocked
	allowed, remaining, _, _ = limiter.check(key, limit, window)
	if allowed {
		t.Error("request exceeding limit should be blocked")
	}
	if remaining != 0 {
		t.Errorf("expected remaining 0, got %d", remaining)
	}
}

func TestInMemoryLimiter_DifferentKeys(t *testing.T) {
	limiter := newInMemoryLimiter()
	defer limiter.Stop()

	limit := 2
	window := time.Minute

	// Exhaust limit for key1
	limiter.check("key1", limit, window)
	limiter.check("key1", limit, window)
	allowed, _, _, _ := limiter.check("key1", limit, window)
	if allowed {
		t.Error("key1 should be rate limited")
	}

	// key2 should have separate limit
	allowed, remaining, _, _ := limiter.check("key2", limit, window)
	if !allowed {
		t.Error("key2 should not be rate limited")
	}
	if remaining != 1 {
		t.Errorf("expected remaining 1 for key2, got %d", remaining)
	}
}

func TestInMemoryLimiter_Cleanup(t *testing.T) {
	limiter := newInMemoryLimiter()
	defer limiter.Stop()

	// Add some entries with short window (they'll be expired)
	window := 10 * time.Millisecond
	limiter.check("expired1", 100, window)
	limiter.check("expired2", 100, window)

	// Wait for window to expire
	time.Sleep(20 * time.Millisecond)

	// Run cleanup
	limiter.cleanup()

	// Entries should be removed - next check should start fresh
	_, remaining, _, _ := limiter.check("expired1", 100, window)
	if remaining != 99 {
		t.Errorf("expected fresh start after cleanup, remaining=%d", remaining)
	}
}

func TestInMemoryLimiter_Stop(t *testing.T) {
	limiter := newInMemoryLimiter()

	// Should not panic
	limiter.Stop()

	// Can still check (no deadlock)
	_, _, _, err := limiter.check("test", 10, time.Minute)
	if err != nil {
		t.Errorf("check after stop should work: %v", err)
	}
}

func TestCheckRateLimit_FallbackOnRedisFailure(t *testing.T) {
	// RateLimiter with nil Redis client should use fallback
	limiter := NewRateLimiter(nil, nil, RateLimitConfig{
		PerIPPerMinute:         100,
		EnableInMemoryFallback: true,
	})

	ctx := context.Background()
	allowed, _, _, err := limiter.checkRateLimit(ctx, "test:key", 100, time.Minute)

	// Should succeed using in-memory fallback
	if !allowed {
		t.Error("expected request to be allowed with fallback")
	}
	if err != nil {
		t.Errorf("expected no error with fallback enabled, got: %v", err)
	}
}

func TestContainsAny(t *testing.T) {
	testCases := []struct {
		s       string
		substrs []string
		want    bool
	}{
		{"/api/v1/users/me/profile", []string{"profile", "users/me"}, true},
		{"/api/v1/addresses", []string{"addresses"}, true},
		{"/api/v1/devices", []string{"profile", "addresses"}, false},
		{"", []string{"test"}, false},
		{"test", []string{}, false},
	}

	for _, tc := range testCases {
		got := containsAny(tc.s, tc.substrs...)
		if got != tc.want {
			t.Errorf("containsAny(%q, %v) = %v, want %v", tc.s, tc.substrs, got, tc.want)
		}
	}
}

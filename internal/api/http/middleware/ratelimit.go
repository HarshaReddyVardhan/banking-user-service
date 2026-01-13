package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/banking/user-service/internal/resilience"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	PerUserPerMinute       int
	PerIPPerMinute         int
	ProfileUpdatesPerHour  int
	AddressChangesPerHour  int
	BurstSize              int
	EnableInMemoryFallback bool
}

// RateLimiter handles multi-tier rate limiting
type RateLimiter struct {
	redis           *redis.Client
	cb              *resilience.CircuitBreaker
	cfg             RateLimitConfig
	inMemoryLimiter *inMemoryLimiter
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(redisClient *redis.Client, cb *resilience.CircuitBreaker, cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		redis:           redisClient,
		cb:              cb,
		cfg:             cfg,
		inMemoryLimiter: newInMemoryLimiter(),
	}
}

// RateLimit middleware applies rate limiting
func (rl *RateLimiter) RateLimit() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			// Determine the rate limit key and limit
			key, limit, window := rl.getRateLimitParams(c)

			// Check rate limit
			allowed, remaining, resetAt, err := rl.checkRateLimit(ctx, key, limit, window)
			if err != nil {
				// Log error but don't block request on rate limiter failure
				// In banking, availability is important
				c.Logger().Warnf("rate limiter error: %v", err)
			}

			// Set rate limit headers
			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))

			if !allowed {
				c.Response().Header().Set("Retry-After", strconv.FormatInt(resetAt-time.Now().Unix(), 10))
				return echo.NewHTTPError(http.StatusTooManyRequests, "rate limit exceeded")
			}

			return next(c)
		}
	}
}

func (rl *RateLimiter) getRateLimitParams(c echo.Context) (key string, limit int, window time.Duration) {
	// Default: per-IP limiting
	ip := c.RealIP()
	key = fmt.Sprintf("v1:ratelimit:ip:%s", ip)
	limit = rl.cfg.PerIPPerMinute
	window = time.Minute

	// If authenticated, use per-user limiting (higher limits)
	if userID, ok := GetUserIDFromEcho(c); ok {
		key = fmt.Sprintf("v1:ratelimit:user:%s", userID.String())
		limit = rl.cfg.PerUserPerMinute

		// Apply resource-specific limits for certain endpoints
		path := c.Path()
		method := c.Request().Method

		if method == "PUT" || method == "POST" || method == "DELETE" {
			if containsAny(path, "profile", "users/me") && method == "PUT" {
				key = fmt.Sprintf("v1:ratelimit:user:%s:profile", userID.String())
				limit = rl.cfg.ProfileUpdatesPerHour
				window = time.Hour
			} else if containsAny(path, "addresses") {
				key = fmt.Sprintf("v1:ratelimit:user:%s:address", userID.String())
				limit = rl.cfg.AddressChangesPerHour
				window = time.Hour
			}
		}
	}

	return key, limit, window
}

func (rl *RateLimiter) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, resetAt int64, err error) {
	// Try Redis first
	result, err := rl.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return rl.checkRedisRateLimit(ctx, key, limit, window)
	})

	if err == nil {
		r := result.(*rateLimitResult)
		return r.allowed, r.remaining, r.resetAt, nil
	}

	// Fallback to in-memory limiter if Redis is down
	if rl.cfg.EnableInMemoryFallback {
		return rl.inMemoryLimiter.check(key, limit, window)
	}

	// If no fallback, allow the request (fail open for availability)
	return true, limit - 1, time.Now().Add(window).Unix(), nil
}

type rateLimitResult struct {
	allowed   bool
	remaining int
	resetAt   int64
}

func (rl *RateLimiter) checkRedisRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*rateLimitResult, error) {
	now := time.Now()
	windowStart := now.Truncate(window)
	resetAt := windowStart.Add(window).Unix()

	// Sliding window rate limiting using Redis
	pipe := rl.redis.Pipeline()

	// Increment counter
	incrCmd := pipe.Incr(ctx, key)
	// Set expiration if new key
	pipe.Expire(ctx, key, window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	count := int(incrCmd.Val())
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &rateLimitResult{
		allowed:   count <= limit,
		remaining: remaining,
		resetAt:   resetAt,
	}, nil
}

// In-memory rate limiter as fallback
type inMemoryLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*bucket
	done    chan struct{}
}

type bucket struct {
	count   int
	resetAt time.Time
}

func newInMemoryLimiter() *inMemoryLimiter {
	limiter := &inMemoryLimiter{
		buckets: make(map[string]*bucket),
		done:    make(chan struct{}),
	}

	// Cleanup goroutine with proper shutdown support
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				limiter.cleanup()
			case <-limiter.done:
				return
			}
		}
	}()

	return limiter
}

// Stop gracefully stops the cleanup goroutine
func (l *inMemoryLimiter) Stop() {
	close(l.done)
}

func (l *inMemoryLimiter) check(key string, limit int, window time.Duration) (allowed bool, remaining int, resetAt int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[key]

	if !exists || now.After(b.resetAt) {
		// New window
		b = &bucket{
			count:   1,
			resetAt: now.Add(window),
		}
		l.buckets[key] = b
		return true, limit - 1, b.resetAt.Unix(), nil
	}

	b.count++
	remaining = limit - b.count
	if remaining < 0 {
		remaining = 0
	}

	return b.count <= limit, remaining, b.resetAt.Unix(), nil
}

func (l *inMemoryLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, b := range l.buckets {
		if now.After(b.resetAt) {
			delete(l.buckets, key)
		}
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsRune(s, substr))
}

func containsRune(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

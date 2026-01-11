package resilience

import (
	"context"
	"errors"
	"time"

	"github.com/sony/gobreaker"
)

// Common errors
var (
	ErrCircuitOpen     = errors.New("circuit breaker is open")
	ErrTooManyRequests = errors.New("too many requests")
)

// CircuitBreakerSettings holds configuration for a circuit breaker
type CircuitBreakerSettings struct {
	Name          string
	MaxRequests   uint32        // Max requests in half-open state
	Interval      time.Duration // Time window for failure count
	Timeout       time.Duration // Time to wait before half-open
	FailureRatio  float64       // Failure ratio to trip
	MinRequests   uint32        // Min requests before evaluation
}

// DefaultSettings returns default circuit breaker settings
func DefaultSettings(name string) CircuitBreakerSettings {
	return CircuitBreakerSettings{
		Name:         name,
		MaxRequests:  3,                // Allow 3 requests in half-open
		Interval:     60 * time.Second, // 1 minute window
		Timeout:      30 * time.Second, // 30 seconds before retry
		FailureRatio: 0.5,              // Trip at 50% failure rate
		MinRequests:  5,                // Need 5 requests before evaluation
	}
}

// CircuitBreaker wraps gobreaker with additional functionality
type CircuitBreaker struct {
	cb       *gobreaker.CircuitBreaker
	name     string
	onOpen   func(name string)
	onClose  func(name string)
}

// NewCircuitBreaker creates a new circuit breaker with the given settings
func NewCircuitBreaker(settings CircuitBreakerSettings) *CircuitBreaker {
	cb := &CircuitBreaker{
		name: settings.Name,
	}

	st := gobreaker.Settings{
		Name:        settings.Name,
		MaxRequests: settings.MaxRequests,
		Interval:    settings.Interval,
		Timeout:     settings.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			if counts.Requests < settings.MinRequests {
				return false
			}
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return failureRatio >= settings.FailureRatio
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			if to == gobreaker.StateOpen && cb.onOpen != nil {
				cb.onOpen(name)
			}
			if to == gobreaker.StateClosed && cb.onClose != nil {
				cb.onClose(name)
			}
		},
	}

	cb.cb = gobreaker.NewCircuitBreaker(st)
	return cb
}

// OnStateChange sets callbacks for state changes
func (c *CircuitBreaker) OnStateChange(onOpen, onClose func(name string)) {
	c.onOpen = onOpen
	c.onClose = onClose
}

// Execute runs a function through the circuit breaker
func (c *CircuitBreaker) Execute(fn func() (interface{}, error)) (interface{}, error) {
	result, err := c.cb.Execute(fn)
	if errors.Is(err, gobreaker.ErrOpenState) {
		return nil, ErrCircuitOpen
	}
	if errors.Is(err, gobreaker.ErrTooManyRequests) {
		return nil, ErrTooManyRequests
	}
	return result, err
}

// ExecuteContext runs a context-aware function through the circuit breaker
func (c *CircuitBreaker) ExecuteContext(ctx context.Context, fn func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	return c.Execute(func() (interface{}, error) {
		return fn(ctx)
	})
}

// State returns the current state of the circuit breaker
func (c *CircuitBreaker) State() string {
	return c.cb.State().String()
}

// IsOpen returns true if the circuit is open
func (c *CircuitBreaker) IsOpen() bool {
	return c.cb.State() == gobreaker.StateOpen
}

// Name returns the circuit breaker name
func (c *CircuitBreaker) Name() string {
	return c.name
}

// Counts returns the current counts
func (c *CircuitBreaker) Counts() gobreaker.Counts {
	return c.cb.Counts()
}

// CircuitBreakers holds all circuit breakers for the service
type CircuitBreakers struct {
	Postgres *CircuitBreaker
	Redis    *CircuitBreaker
	MongoDB  *CircuitBreaker
	Kafka    *CircuitBreaker
}

// NewCircuitBreakers creates circuit breakers for all dependencies
func NewCircuitBreakers() *CircuitBreakers {
	return &CircuitBreakers{
		Postgres: NewCircuitBreaker(DefaultSettings("postgres")),
		Redis:    NewCircuitBreaker(DefaultSettings("redis")),
		MongoDB:  NewCircuitBreaker(DefaultSettings("mongodb")),
		Kafka:    NewCircuitBreaker(DefaultSettings("kafka")),
	}
}

// AllHealthy returns true if no circuit breakers are open
func (cb *CircuitBreakers) AllHealthy() bool {
	return !cb.Postgres.IsOpen() &&
		!cb.Redis.IsOpen() &&
		!cb.MongoDB.IsOpen() &&
		!cb.Kafka.IsOpen()
}

// Status returns the status of all circuit breakers
func (cb *CircuitBreakers) Status() map[string]string {
	return map[string]string{
		"postgres": cb.Postgres.State(),
		"redis":    cb.Redis.State(),
		"mongodb":  cb.MongoDB.State(),
		"kafka":    cb.Kafka.State(),
	}
}

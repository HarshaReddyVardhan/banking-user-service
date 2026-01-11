package resilience

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Common fallback errors
var (
	ErrNoFallback       = errors.New("no fallback available")
	ErrFallbackFailed   = errors.New("fallback execution failed")
	ErrBufferFull       = errors.New("local buffer is full")
)

// FallbackStrategy defines how to handle failures
type FallbackStrategy interface {
	Execute(ctx context.Context, fn func(ctx context.Context) (interface{}, error)) (interface{}, error)
}

// CacheFallback provides fallback to cache when primary fails
type CacheFallback struct {
	primaryCB   *CircuitBreaker
	cacheGetter func(ctx context.Context, key string) (interface{}, error)
}

// NewCacheFallback creates a new cache fallback strategy
func NewCacheFallback(primaryCB *CircuitBreaker, cacheGetter func(ctx context.Context, key string) (interface{}, error)) *CacheFallback {
	return &CacheFallback{
		primaryCB:   primaryCB,
		cacheGetter: cacheGetter,
	}
}

// DatabaseFallback provides fallback to database when cache fails
type DatabaseFallback struct {
	cacheCB    *CircuitBreaker
	dbGetter   func(ctx context.Context, key string) (interface{}, error)
	cacheWrite func(ctx context.Context, key string, value interface{}) error
}

// NewDatabaseFallback creates a new database fallback strategy
func NewDatabaseFallback(
	cacheCB *CircuitBreaker,
	dbGetter func(ctx context.Context, key string) (interface{}, error),
	cacheWrite func(ctx context.Context, key string, value interface{}) error,
) *DatabaseFallback {
	return &DatabaseFallback{
		cacheCB:    cacheCB,
		dbGetter:   dbGetter,
		cacheWrite: cacheWrite,
	}
}

// Execute tries cache first, falls back to database
func (f *DatabaseFallback) Execute(ctx context.Context, key string, cacheGetter func(ctx context.Context) (interface{}, error)) (interface{}, bool, error) {
	// Try cache first (through circuit breaker)
	result, err := f.cacheCB.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return cacheGetter(ctx)
	})

	// Cache hit
	if err == nil && result != nil {
		return result, true, nil
	}

	// Cache miss or circuit open - fall back to database
	result, err = f.dbGetter(ctx, key)
	if err != nil {
		return nil, false, err
	}

	// Async cache population if circuit is closed
	if !f.cacheCB.IsOpen() && f.cacheWrite != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			f.cacheWrite(ctx, key, result)
		}()
	}

	return result, false, nil
}

// DefaultFallback provides default values when service is unavailable
type DefaultFallback struct {
	defaults map[string]interface{}
	mu       sync.RWMutex
}

// NewDefaultFallback creates a fallback that returns default values
func NewDefaultFallback() *DefaultFallback {
	return &DefaultFallback{
		defaults: make(map[string]interface{}),
	}
}

// SetDefault sets a default value for a key
func (f *DefaultFallback) SetDefault(key string, value interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaults[key] = value
}

// Get returns the default value for a key
func (f *DefaultFallback) Get(key string) (interface{}, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	val, ok := f.defaults[key]
	return val, ok
}

// EventBuffer provides local buffering when Kafka is unavailable
type EventBuffer struct {
	mu        sync.Mutex
	events    []BufferedEvent
	maxSize   int
	persist   func(ctx context.Context, events []BufferedEvent) error
	flushFunc func(ctx context.Context, event BufferedEvent) error
}

// BufferedEvent represents an event waiting to be sent
type BufferedEvent struct {
	ID        string          `json:"id"`
	Topic     string          `json:"topic"`
	Key       string          `json:"key"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
	Retries   int             `json:"retries"`
}

// NewEventBuffer creates a new event buffer
func NewEventBuffer(maxSize int, persist func(ctx context.Context, events []BufferedEvent) error) *EventBuffer {
	return &EventBuffer{
		events:  make([]BufferedEvent, 0),
		maxSize: maxSize,
		persist: persist,
	}
}

// SetFlushFunc sets the function to flush events to Kafka
func (b *EventBuffer) SetFlushFunc(fn func(ctx context.Context, event BufferedEvent) error) {
	b.flushFunc = fn
}

// Add adds an event to the buffer
func (b *EventBuffer) Add(event BufferedEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) >= b.maxSize {
		// Persist to database before rejecting
		if b.persist != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := b.persist(ctx, b.events); err == nil {
				b.events = make([]BufferedEvent, 0)
			}
		}

		if len(b.events) >= b.maxSize {
			return ErrBufferFull
		}
	}

	b.events = append(b.events, event)
	return nil
}

// Flush attempts to send all buffered events
func (b *EventBuffer) Flush(ctx context.Context) (int, error) {
	if b.flushFunc == nil {
		return 0, errors.New("no flush function set")
	}

	b.mu.Lock()
	events := make([]BufferedEvent, len(b.events))
	copy(events, b.events)
	b.mu.Unlock()

	flushed := 0
	var lastErr error

	for i, event := range events {
		if err := b.flushFunc(ctx, event); err != nil {
			lastErr = err
			// Update retry count
			events[i].Retries++
		} else {
			flushed++
		}
	}

	// Remove flushed events
	b.mu.Lock()
	remaining := make([]BufferedEvent, 0)
	for _, event := range b.events {
		found := false
		for _, flushedEvent := range events[:flushed] {
			if event.ID == flushedEvent.ID {
				found = true
				break
			}
		}
		if !found {
			remaining = append(remaining, event)
		}
	}
	b.events = remaining
	b.mu.Unlock()

	if lastErr != nil {
		return flushed, fmt.Errorf("flushed %d events, last error: %w", flushed, lastErr)
	}

	return flushed, nil
}

// Size returns the current buffer size
func (b *EventBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// PreferenceDefaults provides default preferences when MongoDB is unavailable
type PreferenceDefaults struct {
	NotificationSettings map[string]bool
	SecurityAlerts       bool
}

// DefaultPreferences returns safe default preferences
func DefaultPreferences() *PreferenceDefaults {
	return &PreferenceDefaults{
		NotificationSettings: map[string]bool{
			"login_alerts":       true,  // Security: always on by default
			"fraud_alerts":       true,  // Security: always on by default
			"transaction_alerts": true,  // Security: always on by default
			"marketing_emails":   false, // Privacy: off by default
		},
		SecurityAlerts: true,
	}
}

package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component
type Status string

const (
	StatusUp      Status = "UP"
	StatusDown    Status = "DOWN"
	StatusUnknown Status = "UNKNOWN"
)

// CheckResult represents the result of a health check
type CheckResult struct {
	Status    Status            `json:"status"`
	Message   string            `json:"message,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status     Status                  `json:"status"`
	Timestamp  time.Time               `json:"timestamp"`
	Components map[string]*CheckResult `json:"components,omitempty"`
}

// Checker is a function that performs a health check
type Checker func(ctx context.Context) *CheckResult

// Health manages health checks for the service
type Health struct {
	mu       sync.RWMutex
	checkers map[string]Checker
	timeout  time.Duration
}

// New creates a new Health manager
func New(timeout time.Duration) *Health {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Health{
		checkers: make(map[string]Checker),
		timeout:  timeout,
	}
}

// Register registers a health checker for a component
func (h *Health) Register(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

// Check runs all health checks and returns the overall health status
func (h *Health) Check(ctx context.Context) *HealthResponse {
	h.mu.RLock()
	checkers := make(map[string]Checker, len(h.checkers))
	for k, v := range h.checkers {
		checkers[k] = v
	}
	h.mu.RUnlock()

	response := &HealthResponse{
		Status:     StatusUp,
		Timestamp:  time.Now().UTC(),
		Components: make(map[string]*CheckResult),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker Checker) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, h.timeout)
			defer cancel()

			result := checker(checkCtx)
			if result == nil {
				result = &CheckResult{
					Status:    StatusUnknown,
					Timestamp: time.Now().UTC(),
				}
			}

			mu.Lock()
			response.Components[name] = result
			if result.Status != StatusUp {
				response.Status = StatusDown
			}
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()
	return response
}

// IsReady returns true if all components are healthy
func (h *Health) IsReady(ctx context.Context) bool {
	response := h.Check(ctx)
	return response.Status == StatusUp
}

// LiveHandler returns an HTTP handler for liveness probe
// Liveness just checks if the process is running
func (h *Health) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    StatusUp,
			"timestamp": time.Now().UTC(),
		})
	}
}

// ReadyHandler returns an HTTP handler for readiness probe
// Readiness checks if the service can accept traffic
func (h *Health) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		response := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if response.Status == StatusUp {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(response)
	}
}

// Common checkers

// PostgresChecker creates a health checker for PostgreSQL
func PostgresChecker(pingFunc func(ctx context.Context) error) Checker {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()
		err := pingFunc(ctx)
		latency := time.Since(start)

		if err != nil {
			return &CheckResult{
				Status:    StatusDown,
				Message:   "PostgreSQL connection failed",
				Timestamp: time.Now().UTC(),
				Details: map[string]string{
					"error":   err.Error(),
					"latency": latency.String(),
				},
			}
		}

		return &CheckResult{
			Status:    StatusUp,
			Timestamp: time.Now().UTC(),
			Details: map[string]string{
				"latency": latency.String(),
			},
		}
	}
}

// RedisChecker creates a health checker for Redis
func RedisChecker(pingFunc func(ctx context.Context) error) Checker {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()
		err := pingFunc(ctx)
		latency := time.Since(start)

		if err != nil {
			return &CheckResult{
				Status:    StatusDown,
				Message:   "Redis connection failed",
				Timestamp: time.Now().UTC(),
				Details: map[string]string{
					"error":   err.Error(),
					"latency": latency.String(),
				},
			}
		}

		return &CheckResult{
			Status:    StatusUp,
			Timestamp: time.Now().UTC(),
			Details: map[string]string{
				"latency": latency.String(),
			},
		}
	}
}

// MongoChecker creates a health checker for MongoDB
func MongoChecker(pingFunc func(ctx context.Context) error) Checker {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()
		err := pingFunc(ctx)
		latency := time.Since(start)

		if err != nil {
			return &CheckResult{
				Status:    StatusDown,
				Message:   "MongoDB connection failed",
				Timestamp: time.Now().UTC(),
				Details: map[string]string{
					"error":   err.Error(),
					"latency": latency.String(),
				},
			}
		}

		return &CheckResult{
			Status:    StatusUp,
			Timestamp: time.Now().UTC(),
			Details: map[string]string{
				"latency": latency.String(),
			},
		}
	}
}

// KafkaChecker creates a health checker for Kafka
func KafkaChecker(checkFunc func(ctx context.Context) error) Checker {
	return func(ctx context.Context) *CheckResult {
		start := time.Now()
		err := checkFunc(ctx)
		latency := time.Since(start)

		if err != nil {
			return &CheckResult{
				Status:    StatusDown,
				Message:   "Kafka connection failed",
				Timestamp: time.Now().UTC(),
				Details: map[string]string{
					"error":   err.Error(),
					"latency": latency.String(),
				},
			}
		}

		return &CheckResult{
			Status:    StatusUp,
			Timestamp: time.Now().UTC(),
			Details: map[string]string{
				"latency": latency.String(),
			},
		}
	}
}

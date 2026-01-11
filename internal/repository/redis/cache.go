package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/resilience"
)

// Common errors
var (
	ErrCacheMiss = errors.New("cache miss")
)

// Cache keys
const (
	userProfilePrefix     = "user:profile:"
	userSummaryPrefix     = "user:summary:"
	userPreferencesPrefix = "user:prefs:"
	deviceListPrefix      = "user:devices:"
)

// UserCache handles caching for user data
type UserCache struct {
	client     *redis.Client
	cb         *resilience.CircuitBreaker
	defaultTTL time.Duration
}

// NewUserCache creates a new user cache
func NewUserCache(client *redis.Client, cb *resilience.CircuitBreaker, defaultTTL time.Duration) *UserCache {
	return &UserCache{
		client:     client,
		cb:         cb,
		defaultTTL: defaultTTL,
	}
}

// UserProfileCache is a cached subset of user profile (minimal PII)
type UserProfileCache struct {
	ID        uuid.UUID          `json:"id"`
	Country   string             `json:"country"`
	Status    domain.UserStatus  `json:"status"`
	KYCStatus domain.KYCStatus   `json:"kyc_status"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// GetProfile retrieves a cached user profile
func (c *UserCache) GetProfile(ctx context.Context, userID uuid.UUID) (*UserProfileCache, error) {
	result, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return c.getProfile(ctx, userID)
	})
	if err != nil {
		if errors.Is(err, resilience.ErrCircuitOpen) {
			return nil, ErrCacheMiss // Treat circuit open as cache miss
		}
		return nil, err
	}
	if result == nil {
		return nil, ErrCacheMiss
	}
	return result.(*UserProfileCache), nil
}

func (c *UserCache) getProfile(ctx context.Context, userID uuid.UUID) (*UserProfileCache, error) {
	key := userProfilePrefix + userID.String()
	
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get profile from cache: %w", err)
	}

	var profile UserProfileCache
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached profile: %w", err)
	}

	return &profile, nil
}

// SetProfile caches a user profile
func (c *UserCache) SetProfile(ctx context.Context, profile *UserProfileCache) error {
	_, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, c.setProfile(ctx, profile)
	})
	return err
}

func (c *UserCache) setProfile(ctx context.Context, profile *UserProfileCache) error {
	key := userProfilePrefix + profile.ID.String()
	
	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := c.client.Set(ctx, key, data, c.defaultTTL).Err(); err != nil {
		return fmt.Errorf("failed to set profile in cache: %w", err)
	}

	return nil
}

// InvalidateProfile removes a user profile from cache
func (c *UserCache) InvalidateProfile(ctx context.Context, userID uuid.UUID) error {
	_, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, c.invalidateProfile(ctx, userID)
	})
	return err
}

func (c *UserCache) invalidateProfile(ctx context.Context, userID uuid.UUID) error {
	key := userProfilePrefix + userID.String()
	return c.client.Del(ctx, key).Err()
}

// GetSummary retrieves a cached user summary (for inter-service calls)
func (c *UserCache) GetSummary(ctx context.Context, userID uuid.UUID) (*domain.UserSummary, error) {
	result, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return c.getSummary(ctx, userID)
	})
	if err != nil {
		if errors.Is(err, resilience.ErrCircuitOpen) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	if result == nil {
		return nil, ErrCacheMiss
	}
	return result.(*domain.UserSummary), nil
}

func (c *UserCache) getSummary(ctx context.Context, userID uuid.UUID) (*domain.UserSummary, error) {
	key := userSummaryPrefix + userID.String()
	
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}

	var summary domain.UserSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, err
	}

	return &summary, nil
}

// SetSummary caches a user summary
func (c *UserCache) SetSummary(ctx context.Context, summary *domain.UserSummary) error {
	_, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, c.setSummary(ctx, summary)
	})
	return err
}

func (c *UserCache) setSummary(ctx context.Context, summary *domain.UserSummary) error {
	key := userSummaryPrefix + summary.ID.String()
	
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}

	// Summary cache has shorter TTL (frequently updated)
	return c.client.Set(ctx, key, data, c.defaultTTL/2).Err()
}

// InvalidateUser removes all cached data for a user
func (c *UserCache) InvalidateUser(ctx context.Context, userID uuid.UUID) error {
	_, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, c.invalidateUser(ctx, userID)
	})
	return err
}

func (c *UserCache) invalidateUser(ctx context.Context, userID uuid.UUID) error {
	keys := []string{
		userProfilePrefix + userID.String(),
		userSummaryPrefix + userID.String(),
		userPreferencesPrefix + userID.String(),
		deviceListPrefix + userID.String(),
	}
	return c.client.Del(ctx, keys...).Err()
}

// Ping checks Redis connectivity
func (c *UserCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// UserFromCache converts a User to UserProfileCache
func UserFromCache(user *domain.User) *UserProfileCache {
	return &UserProfileCache{
		ID:        user.ID,
		Country:   user.Country,
		Status:    user.Status,
		KYCStatus: user.KYCStatus,
		UpdatedAt: user.UpdatedAt,
	}
}

// PreferenceCache caches notification preferences for the notification service
type PreferenceCache struct {
	client     *redis.Client
	cb         *resilience.CircuitBreaker
	defaultTTL time.Duration
}

// NewPreferenceCache creates a new preference cache
func NewPreferenceCache(client *redis.Client, cb *resilience.CircuitBreaker, defaultTTL time.Duration) *PreferenceCache {
	return &PreferenceCache{
		client:     client,
		cb:         cb,
		defaultTTL: defaultTTL,
	}
}

// GetNotificationPrefs retrieves cached notification preferences
func (c *PreferenceCache) GetNotificationPrefs(ctx context.Context, userID uuid.UUID) (*domain.NotificationPreferenceSummary, error) {
	result, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		key := userPreferencesPrefix + userID.String()
		data, err := c.client.Get(ctx, key).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil, ErrCacheMiss
			}
			return nil, err
		}

		var prefs domain.NotificationPreferenceSummary
		if err := json.Unmarshal(data, &prefs); err != nil {
			return nil, err
		}
		return &prefs, nil
	})
	
	if err != nil {
		if errors.Is(err, resilience.ErrCircuitOpen) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	if result == nil {
		return nil, ErrCacheMiss
	}
	return result.(*domain.NotificationPreferenceSummary), nil
}

// SetNotificationPrefs caches notification preferences
func (c *PreferenceCache) SetNotificationPrefs(ctx context.Context, prefs *domain.NotificationPreferenceSummary) error {
	_, err := c.cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		key := userPreferencesPrefix + prefs.UserID.String()
		data, err := json.Marshal(prefs)
		if err != nil {
			return nil, err
		}
		return nil, c.client.Set(ctx, key, data, c.defaultTTL).Err()
	})
	return err
}

package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/domain/audit"
	"github.com/banking/user-service/internal/events"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/repository/postgres"
	"github.com/banking/user-service/internal/repository/redis"
)

// Common service errors
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrOptimisticLock    = errors.New("optimistic lock conflict")
	ErrInvalidInput      = errors.New("invalid input")
)

// UserService handles user-related business logic
type UserService struct {
	userRepo      *postgres.UserRepository
	cache         *redis.UserCache
	auditProducer *events.AuditProducer
	log           *logger.Logger
	hmacSecret    []byte
}

// NewUserService creates a new user service
func NewUserService(
	userRepo *postgres.UserRepository,
	cache *redis.UserCache,
	auditProducer *events.AuditProducer,
	log *logger.Logger,
	hmacSecret []byte,
) *UserService {
	return &UserService{
		userRepo:      userRepo,
		cache:         cache,
		auditProducer: auditProducer,
		log:           log.Named("user_service"),
		hmacSecret:    hmacSecret,
	}
}

// GetProfile retrieves a user profile by ID
func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	// Note: We skip cache here because we need the full profile including PII (decrypted),
	// and the cache only stores a minimal summary (UserProfileCache).
	// For status checks, use GetUserSummary or IsActive which use the cache.

	// Get from database
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Update cache in background with timeout to prevent goroutine leaks
	go func(u *domain.User) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.cache.SetProfile(ctx, redis.UserFromCache(u)); err != nil {
			s.log.Warn("failed to update cache", logger.ErrorField(err))
		}
	}(user)

	return user, nil
}

// UpdateProfile updates a user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, req *domain.UpdateUserRequest, clientIP, requestID string) (*domain.User, error) {
	// Get current user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Track changed fields for audit
	changedFields := []string{}

	// Apply updates
	if req.LegalName != nil && *req.LegalName != user.LegalName {
		user.LegalName = *req.LegalName
		changedFields = append(changedFields, "legal_name")
	}
	if req.Phone != nil && *req.Phone != user.Phone {
		user.Phone = *req.Phone
		changedFields = append(changedFields, "phone")
	}
	if req.Country != nil && *req.Country != user.Country {
		user.Country = *req.Country
		changedFields = append(changedFields, "country")
	}

	if len(changedFields) == 0 {
		return user, nil // No changes
	}

	// Save with optimistic locking
	expectedUpdatedAt := user.UpdatedAt
	err = s.userRepo.Update(ctx, user, expectedUpdatedAt)
	if err != nil {
		if errors.Is(err, postgres.ErrOptimisticLock) {
			return nil, ErrOptimisticLock
		}
		return nil, err
	}

	// Invalidate cache in background with timeout to prevent goroutine leaks
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.cache.InvalidateUser(ctx, id); err != nil {
			s.log.Warn("failed to invalidate cache", logger.ErrorField(err))
		}
	}(userID)

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionUpdate, audit.ResourceProfile, userID.String(), changedFields, clientIP, requestID)

	return user, nil
}

// DeleteProfile soft-deletes a user profile
func (s *UserService) DeleteProfile(ctx context.Context, userID uuid.UUID, clientIP, requestID string) error {
	err := s.userRepo.SoftDelete(ctx, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	// Invalidate cache in background with timeout to prevent goroutine leaks
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.cache.InvalidateUser(ctx, id); err != nil {
			s.log.Warn("failed to invalidate cache", logger.ErrorField(err))
		}
	}(userID)

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionDelete, audit.ResourceProfile, userID.String(), []string{"deleted_at", "status"}, clientIP, requestID)

	return nil
}

// GetUserSummary returns a lean user summary for internal services
func (s *UserService) GetUserSummary(ctx context.Context, userID uuid.UUID) (*domain.UserSummary, error) {
	// Try cache first
	cached, err := s.cache.GetSummary(ctx, userID)
	if err == nil && cached != nil {
		return cached, nil
	}

	// Get from database
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	summary := user.ToSummary()

	// Update cache in background with timeout to prevent goroutine leaks
	go func(s *UserService, sum *domain.UserSummary) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.cache.SetSummary(ctx, sum); err != nil {
			s.log.Warn("failed to update summary cache", logger.ErrorField(err))
		}
	}(s, summary)

	return summary, nil
}

func (s *UserService) emitAuditEvent(ctx context.Context, userID uuid.UUID, action audit.Action, resource audit.Resource, resourceID string, fields []string, clientIP, requestID string) {
	event, err := audit.NewAuditEvent(s.hmacSecret).
		UserID(userID.String()).
		Actor(userID.String(), audit.ActorUser).
		Action(action).
		Resource(resource, resourceID).
		FieldsChanged(fields).
		IPHash(audit.HashIP(clientIP, s.hmacSecret)).
		RequestID(requestID).
		Build()

	if err != nil {
		s.log.Error("failed to build audit event", logger.ErrorField(err))
		return
	}

	if err := s.auditProducer.Produce(ctx, event); err != nil {
		s.log.Error("failed to produce audit event", logger.ErrorField(err))
	}
}

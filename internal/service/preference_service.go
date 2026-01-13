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
)

// Preference service errors
var (
	ErrPreferenceNotFound = errors.New("preference not found")
)

// PreferenceRepository defines the interface for preference storage
type PreferenceRepository interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Preference, error)
	Upsert(ctx context.Context, pref *domain.Preference) error
}

// PreferenceService handles preference-related business logic
type PreferenceService struct {
	prefRepo      PreferenceRepository
	auditProducer *events.AuditProducer
	log           *logger.Logger
	hmacSecret    []byte
}

// NewPreferenceService creates a new preference service
func NewPreferenceService(
	prefRepo PreferenceRepository,
	auditProducer *events.AuditProducer,
	log *logger.Logger,
	hmacSecret []byte,
) *PreferenceService {
	return &PreferenceService{
		prefRepo:      prefRepo,
		auditProducer: auditProducer,
		log:           log.Named("preference_service"),
		hmacSecret:    hmacSecret,
	}
}

// GetPreferences retrieves user preferences
func (s *PreferenceService) GetPreferences(ctx context.Context, userID uuid.UUID) (*domain.Preference, error) {
	pref, err := s.prefRepo.GetByUserID(ctx, userID)
	if err != nil {
		// If not found, return defaults
		return domain.DefaultPreference(userID), nil
	}
	return pref, nil
}

// UpdateUXPreferences updates UX preferences
func (s *PreferenceService) UpdateUXPreferences(ctx context.Context, userID uuid.UUID, req *domain.UpdateUXPreferencesRequest, clientIP, requestID string) (*domain.Preference, error) {
	pref, err := s.prefRepo.GetByUserID(ctx, userID)
	if err != nil {
		// Create default if not exists
		pref = domain.DefaultPreference(userID)
	}

	changedFields := []string{}

	// Apply updates
	if req.Language != nil && *req.Language != pref.UXPreferences.Language {
		pref.UXPreferences.Language = *req.Language
		changedFields = append(changedFields, "language")
	}
	if req.Timezone != nil && *req.Timezone != pref.UXPreferences.Timezone {
		pref.UXPreferences.Timezone = *req.Timezone
		changedFields = append(changedFields, "timezone")
	}
	if req.Theme != nil && *req.Theme != pref.UXPreferences.Theme {
		pref.UXPreferences.Theme = *req.Theme
		changedFields = append(changedFields, "theme")
	}
	if req.DateFormat != nil && *req.DateFormat != pref.UXPreferences.DateFormat {
		pref.UXPreferences.DateFormat = *req.DateFormat
		changedFields = append(changedFields, "date_format")
	}
	if req.Currency != nil && *req.Currency != pref.UXPreferences.Currency {
		pref.UXPreferences.Currency = *req.Currency
		changedFields = append(changedFields, "currency")
	}
	if req.AccessibilityMode != nil && *req.AccessibilityMode != pref.UXPreferences.AccessibilityMode {
		pref.UXPreferences.AccessibilityMode = *req.AccessibilityMode
		changedFields = append(changedFields, "accessibility_mode")
	}
	if req.ReducedMotion != nil && *req.ReducedMotion != pref.UXPreferences.ReducedMotion {
		pref.UXPreferences.ReducedMotion = *req.ReducedMotion
		changedFields = append(changedFields, "reduced_motion")
	}
	if req.HighContrast != nil && *req.HighContrast != pref.UXPreferences.HighContrast {
		pref.UXPreferences.HighContrast = *req.HighContrast
		changedFields = append(changedFields, "high_contrast")
	}

	if len(changedFields) == 0 {
		return pref, nil // No changes
	}

	pref.UpdatedAt = time.Now().UTC()
	if err := s.prefRepo.Upsert(ctx, pref); err != nil {
		return nil, err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionUpdate, audit.ResourcePreference, userID.String(), changedFields, clientIP, requestID)

	return pref, nil
}

// UpdateNotificationSettings updates notification preferences
func (s *PreferenceService) UpdateNotificationSettings(ctx context.Context, userID uuid.UUID, req *domain.UpdateNotificationRequest, clientIP, requestID string) (*domain.Preference, error) {
	pref, err := s.prefRepo.GetByUserID(ctx, userID)
	if err != nil {
		// Create default if not exists
		pref = domain.DefaultPreference(userID)
	}

	changedFields := []string{}

	// Security notifications cannot be fully disabled
	if domain.IsSecurityNotification(req.Type) && req.Enabled != nil && !*req.Enabled {
		// Don't allow disabling security notifications entirely
		s.log.Warn("attempted to disable security notification")
	}

	setting, exists := pref.NotificationSettings[req.Type]
	if !exists {
		setting = domain.NotificationSetting{
			Enabled:  true,
			Channels: []domain.NotificationChannel{},
		}
	}

	if req.Enabled != nil && *req.Enabled != setting.Enabled {
		// Only allow disabling non-security notifications
		if !domain.IsSecurityNotification(req.Type) || *req.Enabled {
			setting.Enabled = *req.Enabled
			changedFields = append(changedFields, string(req.Type)+"_enabled")
		}
	}
	if req.Channels != nil {
		setting.Channels = req.Channels
		changedFields = append(changedFields, string(req.Type)+"_channels")
	}

	pref.NotificationSettings[req.Type] = setting

	if len(changedFields) == 0 {
		return pref, nil
	}

	pref.UpdatedAt = time.Now().UTC()
	if err := s.prefRepo.Upsert(ctx, pref); err != nil {
		return nil, err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionUpdate, audit.ResourcePreference, userID.String(), changedFields, clientIP, requestID)

	return pref, nil
}

func (s *PreferenceService) emitAuditEvent(ctx context.Context, userID uuid.UUID, action audit.Action, resource audit.Resource, resourceID string, fields []string, clientIP, requestID string) {
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

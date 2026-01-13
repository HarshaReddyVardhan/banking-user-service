package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/domain/audit"
	"github.com/banking/user-service/internal/events"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/repository/postgres"
)

// Device service errors
var (
	ErrDeviceNotFound = errors.New("device not found")
)

// DeviceService handles device-related business logic
type DeviceService struct {
	deviceRepo    *postgres.DeviceRepository
	auditProducer *events.AuditProducer
	log           *logger.Logger
	hmacSecret    []byte
}

// NewDeviceService creates a new device service
func NewDeviceService(
	deviceRepo *postgres.DeviceRepository,
	auditProducer *events.AuditProducer,
	log *logger.Logger,
	hmacSecret []byte,
) *DeviceService {
	return &DeviceService{
		deviceRepo:    deviceRepo,
		auditProducer: auditProducer,
		log:           log.Named("device_service"),
		hmacSecret:    hmacSecret,
	}
}

// ListDevices retrieves all devices for a user
func (s *DeviceService) ListDevices(ctx context.Context, userID uuid.UUID, currentFingerprint string) ([]*domain.DeviceListItem, error) {
	devices, err := s.deviceRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	currentHash := ""
	if currentFingerprint != "" {
		currentHash = s.deviceRepo.HashFingerprint(currentFingerprint)
	}

	items := make([]*domain.DeviceListItem, 0, len(devices))
	for _, device := range devices {
		items = append(items, device.ToListItem(currentHash))
	}

	return items, nil
}

// RemoveDevice soft-deletes a device
func (s *DeviceService) RemoveDevice(ctx context.Context, userID, deviceID uuid.UUID, clientIP, requestID string) error {
	err := s.deviceRepo.SoftDelete(ctx, userID, deviceID)
	if err != nil {
		if errors.Is(err, postgres.ErrDeviceNotFound) {
			return ErrDeviceNotFound
		}
		return err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionDelete, audit.ResourceDevice, deviceID.String(), []string{"deleted_at"}, clientIP, requestID)

	return nil
}

func (s *DeviceService) emitAuditEvent(ctx context.Context, userID uuid.UUID, action audit.Action, resource audit.Resource, resourceID string, fields []string, clientIP, requestID string) {
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

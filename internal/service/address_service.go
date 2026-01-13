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

// Address service errors
var (
	ErrAddressNotFound = errors.New("address not found")
)

// AddressService handles address-related business logic
type AddressService struct {
	addressRepo   *postgres.AddressRepository
	auditProducer *events.AuditProducer
	log           *logger.Logger
	hmacSecret    []byte
}

// NewAddressService creates a new address service
func NewAddressService(
	addressRepo *postgres.AddressRepository,
	auditProducer *events.AuditProducer,
	log *logger.Logger,
	hmacSecret []byte,
) *AddressService {
	return &AddressService{
		addressRepo:   addressRepo,
		auditProducer: auditProducer,
		log:           log.Named("address_service"),
		hmacSecret:    hmacSecret,
	}
}

// ListAddresses retrieves all addresses for a user
func (s *AddressService) ListAddresses(ctx context.Context, userID uuid.UUID) ([]*domain.Address, error) {
	addresses, err := s.addressRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return addresses, nil
}

// CreateAddress creates a new address for a user
func (s *AddressService) CreateAddress(ctx context.Context, userID uuid.UUID, req *domain.CreateAddressRequest, clientIP, requestID string) (*domain.Address, error) {
	addr := &domain.Address{
		UserID:      userID,
		AddressType: req.AddressType,
		StreetLine1: req.StreetLine1,
		StreetLine2: req.StreetLine2,
		City:        req.City,
		State:       req.State,
		PostalCode:  req.PostalCode,
		Country:     req.Country,
		IsPrimary:   req.IsPrimary,
	}

	if err := s.addressRepo.Create(ctx, addr); err != nil {
		return nil, err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionCreate, audit.ResourceAddress, addr.ID.String(),
		[]string{"address_type", "street_line_1", "city", "country"}, clientIP, requestID)

	return addr, nil
}

// GetAddress retrieves a specific address by ID
func (s *AddressService) GetAddress(ctx context.Context, userID, addressID uuid.UUID) (*domain.Address, error) {
	addr, err := s.addressRepo.GetByID(ctx, userID, addressID)
	if err != nil {
		if errors.Is(err, postgres.ErrAddressNotFound) {
			return nil, ErrAddressNotFound
		}
		return nil, err
	}
	return addr, nil
}

// UpdateAddress updates an existing address
func (s *AddressService) UpdateAddress(ctx context.Context, userID, addressID uuid.UUID, req *domain.UpdateAddressRequest, clientIP, requestID string) (*domain.Address, error) {
	addr, err := s.addressRepo.GetByID(ctx, userID, addressID)
	if err != nil {
		if errors.Is(err, postgres.ErrAddressNotFound) {
			return nil, ErrAddressNotFound
		}
		return nil, err
	}

	changedFields := []string{}

	// Apply updates
	if req.AddressType != nil && *req.AddressType != addr.AddressType {
		addr.AddressType = *req.AddressType
		changedFields = append(changedFields, "address_type")
	}
	if req.StreetLine1 != nil && *req.StreetLine1 != addr.StreetLine1 {
		addr.StreetLine1 = *req.StreetLine1
		changedFields = append(changedFields, "street_line_1")
	}
	if req.StreetLine2 != nil && *req.StreetLine2 != addr.StreetLine2 {
		addr.StreetLine2 = *req.StreetLine2
		changedFields = append(changedFields, "street_line_2")
	}
	if req.City != nil && *req.City != addr.City {
		addr.City = *req.City
		changedFields = append(changedFields, "city")
	}
	if req.State != nil && *req.State != addr.State {
		addr.State = *req.State
		changedFields = append(changedFields, "state")
	}
	if req.PostalCode != nil && *req.PostalCode != addr.PostalCode {
		addr.PostalCode = *req.PostalCode
		changedFields = append(changedFields, "postal_code")
	}
	if req.Country != nil && *req.Country != addr.Country {
		addr.Country = *req.Country
		changedFields = append(changedFields, "country")
	}
	if req.IsPrimary != nil && *req.IsPrimary != addr.IsPrimary {
		addr.IsPrimary = *req.IsPrimary
		changedFields = append(changedFields, "is_primary")
	}

	if len(changedFields) == 0 {
		return addr, nil // No changes
	}

	if err := s.addressRepo.Update(ctx, addr); err != nil {
		return nil, err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionUpdate, audit.ResourceAddress, addr.ID.String(), changedFields, clientIP, requestID)

	return addr, nil
}

// DeleteAddress soft-deletes an address
func (s *AddressService) DeleteAddress(ctx context.Context, userID, addressID uuid.UUID, clientIP, requestID string) error {
	err := s.addressRepo.SoftDelete(ctx, userID, addressID)
	if err != nil {
		if errors.Is(err, postgres.ErrAddressNotFound) {
			return ErrAddressNotFound
		}
		return err
	}

	// Emit audit event
	s.emitAuditEvent(ctx, userID, audit.ActionDelete, audit.ResourceAddress, addressID.String(), []string{"deleted_at"}, clientIP, requestID)

	return nil
}

func (s *AddressService) emitAuditEvent(ctx context.Context, userID uuid.UUID, action audit.Action, resource audit.Resource, resourceID string, fields []string, clientIP, requestID string) {
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

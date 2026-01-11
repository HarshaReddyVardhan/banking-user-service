package domain

import (
	"time"

	"github.com/google/uuid"
)

// AddressType represents the type of address
type AddressType string

const (
	AddressTypeBilling     AddressType = "BILLING"
	AddressTypeResidential AddressType = "RESIDENTIAL"
	AddressTypeMailing     AddressType = "MAILING"
	AddressTypeTemporary   AddressType = "TEMPORARY"
)

// ValidationStatus represents address validation status
type ValidationStatus string

const (
	ValidationStatusPending   ValidationStatus = "PENDING"
	ValidationStatusValid     ValidationStatus = "VALID"
	ValidationStatusInvalid   ValidationStatus = "INVALID"
	ValidationStatusUnknown   ValidationStatus = "UNKNOWN"
)

// Address represents a user address entity
// Address data is treated as HIGH PII and stored encrypted
type Address struct {
	ID                   uuid.UUID        `json:"id" db:"id"`
	UserID               uuid.UUID        `json:"user_id" db:"user_id"`
	AddressType          AddressType      `json:"address_type" db:"address_type"`
	
	// Decrypted fields (not stored directly)
	StreetLine1          string           `json:"street_line_1" db:"-"`
	StreetLine2          string           `json:"street_line_2,omitempty" db:"-"`
	City                 string           `json:"city" db:"-"`
	State                string           `json:"state,omitempty" db:"-"`
	PostalCode           string           `json:"postal_code" db:"-"`
	Country              string           `json:"country" db:"-"` // ISO 3166-1 alpha-2
	
	// Encrypted compound field
	AddressEncrypted     string           `json:"-" db:"address_encrypted"`
	
	IsPrimary            bool             `json:"is_primary" db:"is_primary"`
	ValidationStatus     ValidationStatus `json:"validation_status" db:"validation_status"`
	ValidationSource     string           `json:"validation_source,omitempty" db:"validation_source"`
	ValidatedAt          *time.Time       `json:"validated_at,omitempty" db:"validated_at"`
	Version              int              `json:"version" db:"version"`
	EncryptionKeyVersion int              `json:"-" db:"encryption_key_version"`
	CreatedAt            time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at" db:"updated_at"`
	DeletedAt            *time.Time       `json:"-" db:"deleted_at"`
}

// AddressData holds the decrypted address components
type AddressData struct {
	StreetLine1 string `json:"street_line_1"`
	StreetLine2 string `json:"street_line_2,omitempty"`
	City        string `json:"city"`
	State       string `json:"state,omitempty"`
	PostalCode  string `json:"postal_code"`
	Country     string `json:"country"`
}

// ToAddressData extracts address data from an Address
func (a *Address) ToAddressData() *AddressData {
	return &AddressData{
		StreetLine1: a.StreetLine1,
		StreetLine2: a.StreetLine2,
		City:        a.City,
		State:       a.State,
		PostalCode:  a.PostalCode,
		Country:     a.Country,
	}
}

// FromAddressData populates address fields from AddressData
func (a *Address) FromAddressData(data *AddressData) {
	a.StreetLine1 = data.StreetLine1
	a.StreetLine2 = data.StreetLine2
	a.City = data.City
	a.State = data.State
	a.PostalCode = data.PostalCode
	a.Country = data.Country
}

// IsDeleted returns true if the address is soft-deleted
func (a *Address) IsDeleted() bool {
	return a.DeletedAt != nil
}

// IsValidated returns true if address has been validated
func (a *Address) IsValidated() bool {
	return a.ValidationStatus == ValidationStatusValid
}

// AddressHistory represents a historical version of an address
type AddressHistory struct {
	ID               uuid.UUID   `json:"id" db:"id"`
	AddressID        uuid.UUID   `json:"address_id" db:"address_id"`
	UserID           uuid.UUID   `json:"user_id" db:"user_id"`
	AddressEncrypted string      `json:"-" db:"address_encrypted"`
	Version          int         `json:"version" db:"version"`
	ChangedBy        string      `json:"changed_by" db:"changed_by"`
	ChangeSource     string      `json:"change_source" db:"change_source"` // USER, ADMIN, SYSTEM
	CreatedAt        time.Time   `json:"created_at" db:"created_at"`
}

// CreateAddressRequest represents a request to create an address
type CreateAddressRequest struct {
	AddressType AddressType `json:"address_type" validate:"required,oneof=BILLING RESIDENTIAL MAILING TEMPORARY"`
	StreetLine1 string      `json:"street_line_1" validate:"required,min=1,max=200"`
	StreetLine2 string      `json:"street_line_2,omitempty" validate:"max=200"`
	City        string      `json:"city" validate:"required,min=1,max=100"`
	State       string      `json:"state,omitempty" validate:"max=100"`
	PostalCode  string      `json:"postal_code" validate:"required,min=1,max=20"`
	Country     string      `json:"country" validate:"required,iso3166_1_alpha2"`
	IsPrimary   bool        `json:"is_primary"`
}

// UpdateAddressRequest represents a request to update an address
type UpdateAddressRequest struct {
	AddressType *AddressType `json:"address_type,omitempty" validate:"omitempty,oneof=BILLING RESIDENTIAL MAILING TEMPORARY"`
	StreetLine1 *string      `json:"street_line_1,omitempty" validate:"omitempty,min=1,max=200"`
	StreetLine2 *string      `json:"street_line_2,omitempty" validate:"omitempty,max=200"`
	City        *string      `json:"city,omitempty" validate:"omitempty,min=1,max=100"`
	State       *string      `json:"state,omitempty" validate:"omitempty,max=100"`
	PostalCode  *string      `json:"postal_code,omitempty" validate:"omitempty,min=1,max=20"`
	Country     *string      `json:"country,omitempty" validate:"omitempty,iso3166_1_alpha2"`
	IsPrimary   *bool        `json:"is_primary,omitempty"`
}

// AddressSummary is a minimal address representation
type AddressSummary struct {
	ID          uuid.UUID   `json:"id"`
	AddressType AddressType `json:"address_type"`
	City        string      `json:"city"`
	Country     string      `json:"country"`
	IsPrimary   bool        `json:"is_primary"`
}

// ToSummary converts an Address to AddressSummary
func (a *Address) ToSummary() *AddressSummary {
	return &AddressSummary{
		ID:          a.ID,
		AddressType: a.AddressType,
		City:        a.City,
		Country:     a.Country,
		IsPrimary:   a.IsPrimary,
	}
}

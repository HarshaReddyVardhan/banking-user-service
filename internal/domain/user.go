package domain

import (
	"time"

	"github.com/google/uuid"
)

// PIISensitivity classifies data sensitivity levels
type PIISensitivity string

const (
	PIIHigh   PIISensitivity = "HIGH"   // legal name, DOB, email, phone, address
	PIIMedium PIISensitivity = "MEDIUM" // device metadata, KYC status
	PIILow    PIISensitivity = "LOW"    // preferences, feature flags
)

// UserStatus represents the status of a user account
type UserStatus string

const (
	UserStatusActive    UserStatus = "ACTIVE"
	UserStatusSuspended UserStatus = "SUSPENDED"
	UserStatusPending   UserStatus = "PENDING"
	UserStatusDeleted   UserStatus = "DELETED" // Soft deleted
)

// KYCStatus represents the KYC verification status
type KYCStatus string

const (
	KYCStatusPending  KYCStatus = "PENDING"
	KYCStatusApproved KYCStatus = "APPROVED"
	KYCStatusRejected KYCStatus = "REJECTED"
	KYCStatusExpired  KYCStatus = "EXPIRED"
)

// User represents a user profile entity
// PII fields are stored encrypted in the database
type User struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	LegalName            string     `json:"legal_name" db:"-"`             // Decrypted, HIGH PII
	LegalNameEncrypted   string     `json:"-" db:"legal_name_encrypted"`   // Stored encrypted
	Email                string     `json:"email" db:"-"`                  // Decrypted, HIGH PII
	EmailEncrypted       string     `json:"-" db:"email_encrypted"`        // Stored encrypted
	EmailHash            string     `json:"-" db:"email_hash"`             // For lookups
	Phone                string     `json:"phone,omitempty" db:"-"`        // Decrypted, HIGH PII
	PhoneEncrypted       *string    `json:"-" db:"phone_encrypted"`        // Stored encrypted
	PhoneHash            *string    `json:"-" db:"phone_hash"`             // For lookups
	DOB                  *time.Time `json:"dob,omitempty" db:"-"`          // Decrypted, HIGH PII
	DOBEncrypted         *string    `json:"-" db:"dob_encrypted"`          // Stored encrypted
	Country              string     `json:"country" db:"country"`          // ISO 3166-1 alpha-2
	Status               UserStatus `json:"status" db:"status"`
	KYCStatus            KYCStatus  `json:"kyc_status" db:"kyc_status"`
	KYCReferenceID       *uuid.UUID `json:"kyc_reference_id,omitempty" db:"kyc_reference_id"`
	RiskFlags            []string   `json:"risk_flags,omitempty" db:"risk_flags"`
	EncryptionKeyVersion int        `json:"-" db:"encryption_key_version"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt            *time.Time `json:"-" db:"deleted_at"` // Soft delete
}

// IsActive returns true if the user is active
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive && u.DeletedAt == nil
}

// IsDeleted returns true if the user is soft-deleted
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil || u.Status == UserStatusDeleted
}

// CanPerformHighRiskOps returns true if user can perform high-risk operations
func (u *User) CanPerformHighRiskOps() bool {
	return u.IsActive() && u.KYCStatus == KYCStatusApproved
}

// HasRiskFlag checks if user has a specific risk flag
func (u *User) HasRiskFlag(flag string) bool {
	for _, f := range u.RiskFlags {
		if f == flag {
			return true
		}
	}
	return false
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	LegalName string `json:"legal_name" validate:"required,min=2,max=100"`
	Email     string `json:"email" validate:"required,email"`
	Phone     string `json:"phone,omitempty" validate:"omitempty,e164"`
	DOB       string `json:"dob,omitempty" validate:"omitempty,datetime=2006-01-02"`
	Country   string `json:"country" validate:"required,iso3166_1_alpha2"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	LegalName *string `json:"legal_name,omitempty" validate:"omitempty,min=2,max=100"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,e164"`
	Country   *string `json:"country,omitempty" validate:"omitempty,iso3166_1_alpha2"`
}

// UserSummary is a lean DTO for other services (minimal PII)
type UserSummary struct {
	ID        uuid.UUID  `json:"id"`
	Country   string     `json:"country"`
	Status    UserStatus `json:"status"`
	KYCStatus KYCStatus  `json:"kyc_status"`
	RiskFlags []string   `json:"risk_flags,omitempty"`
}

// ToSummary converts a User to UserSummary
func (u *User) ToSummary() *UserSummary {
	return &UserSummary{
		ID:        u.ID,
		Country:   u.Country,
		Status:    u.Status,
		KYCStatus: u.KYCStatus,
		RiskFlags: u.RiskFlags,
	}
}

// MaskedEmail returns a masked email for logging/display
func (u *User) MaskedEmail() string {
	if u.Email == "" {
		return ""
	}
	return maskEmail(u.Email)
}

// MaskedPhone returns a masked phone for logging/display
func (u *User) MaskedPhone() string {
	if u.Phone == "" {
		return ""
	}
	return maskPhone(u.Phone)
}

func maskEmail(email string) string {
	// Implementation matches logger's maskEmail
	if len(email) < 3 {
		return "***"
	}
	atIdx := -1
	for i, c := range email {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx <= 0 {
		return "***"
	}
	return string(email[0]) + "***" + email[atIdx:]
}

func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:2] + "***" + phone[len(phone)-4:]
}

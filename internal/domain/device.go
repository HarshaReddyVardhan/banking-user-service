package domain

import (
	"time"

	"github.com/google/uuid"
)

// DeviceType represents the type of device
type DeviceType string

const (
	DeviceTypeMobile  DeviceType = "MOBILE"
	DeviceTypeTablet  DeviceType = "TABLET"
	DeviceTypeDesktop DeviceType = "DESKTOP"
	DeviceTypeWeb     DeviceType = "WEB"
	DeviceTypeUnknown DeviceType = "UNKNOWN"
)

// DeviceOS represents the operating system
type DeviceOS string

const (
	DeviceOSiOS     DeviceOS = "iOS"
	DeviceOSAndroid DeviceOS = "ANDROID"
	DeviceOSWindows DeviceOS = "WINDOWS"
	DeviceOSMacOS   DeviceOS = "MACOS"
	DeviceOSLinux   DeviceOS = "LINUX"
	DeviceOSWeb     DeviceOS = "WEB"
	DeviceOSUnknown DeviceOS = "UNKNOWN"
)

// Device represents a registered device for a user
// Device fingerprint and IP are stored as hashes for privacy
type Device struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	FingerprintHash string     `json:"-" db:"fingerprint_hash"` // SHA-256 hash, never raw
	DeviceType      DeviceType `json:"device_type" db:"device_type"`
	OS              DeviceOS   `json:"os" db:"os"`
	OSVersion       string     `json:"os_version,omitempty" db:"os_version"`
	AppVersion      string     `json:"app_version,omitempty" db:"app_version"`
	DeviceName      string     `json:"device_name,omitempty" db:"device_name"` // User-facing name like "John's iPhone"
	LastIPHash      string     `json:"-" db:"last_ip_hash"`                    // Hashed for privacy
	LastActiveAt    *time.Time `json:"last_active_at,omitempty" db:"last_active_at"`
	IsTrusted       bool       `json:"is_trusted" db:"is_trusted"`
	TrustReason     string     `json:"trust_reason,omitempty" db:"trust_reason"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	DeletedAt       *time.Time `json:"-" db:"deleted_at"`
}

// IsActive returns true if device is not deleted
func (d *Device) IsActive() bool {
	return d.DeletedAt == nil
}

// WasActiveRecently returns true if device was active in the last N days
func (d *Device) WasActiveRecently(days int) bool {
	if d.LastActiveAt == nil {
		return false
	}
	threshold := time.Now().AddDate(0, 0, -days)
	return d.LastActiveAt.After(threshold)
}

// DeviceSuspicion indicates fraud-related signals
type DeviceSuspicion struct {
	IsNewDevice       bool   `json:"is_new_device"`        // First time seeing this device
	UnusualLocation   bool   `json:"unusual_location"`     // IP location differs from normal
	MultipleUsers     bool   `json:"multiple_users"`       // Device used by multiple users
	RapidLocationChange bool `json:"rapid_location_change"` // Impossible travel
	SuspicionScore    int    `json:"suspicion_score"`      // 0-100
	Reasons           []string `json:"reasons,omitempty"`
}

// RegisterDeviceRequest represents a request to register a device
type RegisterDeviceRequest struct {
	Fingerprint string     `json:"fingerprint" validate:"required,min=32,max=128"`
	DeviceType  DeviceType `json:"device_type" validate:"required,oneof=MOBILE TABLET DESKTOP WEB UNKNOWN"`
	OS          DeviceOS   `json:"os" validate:"required"`
	OSVersion   string     `json:"os_version,omitempty" validate:"max=50"`
	AppVersion  string     `json:"app_version,omitempty" validate:"max=20"`
	DeviceName  string     `json:"device_name,omitempty" validate:"max=100"`
	IP          string     `json:"-"` // Set from request headers, not user input
}

// DeviceListItem is a summary for device listing
type DeviceListItem struct {
	ID           uuid.UUID  `json:"id"`
	DeviceType   DeviceType `json:"device_type"`
	OS           DeviceOS   `json:"os"`
	DeviceName   string     `json:"device_name,omitempty"`
	IsTrusted    bool       `json:"is_trusted"`
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
	IsCurrent    bool       `json:"is_current"` // Is this the device making the request
}

// ToListItem converts a Device to DeviceListItem
func (d *Device) ToListItem(currentFingerprintHash string) *DeviceListItem {
	return &DeviceListItem{
		ID:           d.ID,
		DeviceType:   d.DeviceType,
		OS:           d.OS,
		DeviceName:   d.DeviceName,
		IsTrusted:    d.IsTrusted,
		LastActiveAt: d.LastActiveAt,
		IsCurrent:    d.FingerprintHash == currentFingerprintHash,
	}
}

// DeviceForFraud is the data sent to fraud service (internal only)
type DeviceForFraud struct {
	DeviceID        uuid.UUID  `json:"device_id"`
	UserID          uuid.UUID  `json:"user_id"`
	FingerprintHash string     `json:"fingerprint_hash"`
	DeviceType      DeviceType `json:"device_type"`
	OS              DeviceOS   `json:"os"`
	OSVersion       string     `json:"os_version,omitempty"`
	LastIPHash      string     `json:"last_ip_hash"`
	LastActiveAt    *time.Time `json:"last_active_at,omitempty"`
	IsTrusted       bool       `json:"is_trusted"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ToFraudData converts a Device to DeviceForFraud
func (d *Device) ToFraudData() *DeviceForFraud {
	return &DeviceForFraud{
		DeviceID:        d.ID,
		UserID:          d.UserID,
		FingerprintHash: d.FingerprintHash,
		DeviceType:      d.DeviceType,
		OS:              d.OS,
		OSVersion:       d.OSVersion,
		LastIPHash:      d.LastIPHash,
		LastActiveAt:    d.LastActiveAt,
		IsTrusted:       d.IsTrusted,
		CreatedAt:       d.CreatedAt,
	}
}

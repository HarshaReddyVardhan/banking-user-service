package domain

import (
	"time"

	"github.com/google/uuid"
)

// NotificationType represents types of notifications
type NotificationType string

const (
	NotificationLoginAlert      NotificationType = "LOGIN_ALERT"
	NotificationFraudAlert      NotificationType = "FRAUD_ALERT"
	NotificationTransactionAlert NotificationType = "TRANSACTION_ALERT"
	NotificationSecurityAlert   NotificationType = "SECURITY_ALERT"
	NotificationMarketingEmail  NotificationType = "MARKETING_EMAIL"
	NotificationProductUpdate   NotificationType = "PRODUCT_UPDATE"
)

// NotificationChannel represents how to deliver notifications
type NotificationChannel string

const (
	ChannelEmail     NotificationChannel = "EMAIL"
	ChannelSMS       NotificationChannel = "SMS"
	ChannelPush      NotificationChannel = "PUSH"
	ChannelWebSocket NotificationChannel = "WEBSOCKET"
	ChannelInApp     NotificationChannel = "IN_APP"
)

// Theme represents UI theme preference
type Theme string

const (
	ThemeLight  Theme = "LIGHT"
	ThemeDark   Theme = "DARK"
	ThemeSystem Theme = "SYSTEM"
)

// Preference represents user preferences
// Stored in MongoDB for schema flexibility
type Preference struct {
	ID                    string                                    `json:"id" bson:"_id"`
	UserID                uuid.UUID                                 `json:"user_id" bson:"user_id"`
	NotificationSettings  map[NotificationType]NotificationSetting  `json:"notification_settings" bson:"notification_settings"`
	UXPreferences         UXPreferences                             `json:"ux_preferences" bson:"ux_preferences"`
	FeatureFlags          map[string]bool                           `json:"feature_flags" bson:"feature_flags"`
	CustomSettings        map[string]interface{}                    `json:"custom_settings,omitempty" bson:"custom_settings,omitempty"`
	UpdatedAt             time.Time                                 `json:"updated_at" bson:"updated_at"`
}

// NotificationSetting defines settings for a notification type
type NotificationSetting struct {
	Enabled   bool                   `json:"enabled" bson:"enabled"`
	Channels  []NotificationChannel  `json:"channels" bson:"channels"`
	Quiet     *QuietHours            `json:"quiet,omitempty" bson:"quiet,omitempty"`
}

// QuietHours defines when not to send notifications
type QuietHours struct {
	Enabled   bool   `json:"enabled" bson:"enabled"`
	StartHour int    `json:"start_hour" bson:"start_hour"` // 0-23
	EndHour   int    `json:"end_hour" bson:"end_hour"`     // 0-23
	Timezone  string `json:"timezone" bson:"timezone"`
}

// UXPreferences holds user experience preferences
type UXPreferences struct {
	Language              string  `json:"language" bson:"language"`                             // e.g., "en", "es", "fr"
	Timezone              string  `json:"timezone" bson:"timezone"`                             // IANA timezone
	Theme                 Theme   `json:"theme" bson:"theme"`
	DateFormat            string  `json:"date_format" bson:"date_format"`                       // e.g., "MM/DD/YYYY"
	Currency              string  `json:"currency" bson:"currency"`                             // ISO 4217
	AccessibilityMode     bool    `json:"accessibility_mode" bson:"accessibility_mode"`
	ReducedMotion         bool    `json:"reduced_motion" bson:"reduced_motion"`
	HighContrast          bool    `json:"high_contrast" bson:"high_contrast"`
}

// DefaultPreference creates default preferences for a new user
func DefaultPreference(userID uuid.UUID) *Preference {
	return &Preference{
		ID:     uuid.New().String(),
		UserID: userID,
		NotificationSettings: map[NotificationType]NotificationSetting{
			// Security notifications - always enabled by default
			NotificationLoginAlert: {
				Enabled:  true,
				Channels: []NotificationChannel{ChannelEmail, ChannelPush},
			},
			NotificationFraudAlert: {
				Enabled:  true,
				Channels: []NotificationChannel{ChannelEmail, ChannelSMS, ChannelPush},
			},
			NotificationTransactionAlert: {
				Enabled:  true,
				Channels: []NotificationChannel{ChannelPush, ChannelInApp},
			},
			NotificationSecurityAlert: {
				Enabled:  true,
				Channels: []NotificationChannel{ChannelEmail, ChannelSMS, ChannelPush},
			},
			// Marketing - disabled by default (privacy)
			NotificationMarketingEmail: {
				Enabled:  false,
				Channels: []NotificationChannel{ChannelEmail},
			},
			NotificationProductUpdate: {
				Enabled:  false,
				Channels: []NotificationChannel{ChannelEmail, ChannelInApp},
			},
		},
		UXPreferences: UXPreferences{
			Language:  "en",
			Timezone:  "UTC",
			Theme:     ThemeSystem,
			DateFormat: "YYYY-MM-DD",
			Currency:  "USD",
		},
		FeatureFlags: make(map[string]bool),
		UpdatedAt:    time.Now().UTC(),
	}
}

// IsSecurityNotification returns true if notification type is security-related
func IsSecurityNotification(t NotificationType) bool {
	switch t {
	case NotificationLoginAlert, NotificationFraudAlert, NotificationSecurityAlert:
		return true
	default:
		return false
	}
}

// UpdateNotificationRequest represents a request to update notification settings
type UpdateNotificationRequest struct {
	Type     NotificationType   `json:"type" validate:"required"`
	Enabled  *bool              `json:"enabled,omitempty"`
	Channels []NotificationChannel `json:"channels,omitempty"`
}

// UpdateUXPreferencesRequest represents a request to update UX preferences
type UpdateUXPreferencesRequest struct {
	Language          *string `json:"language,omitempty" validate:"omitempty,min=2,max=5"`
	Timezone          *string `json:"timezone,omitempty" validate:"omitempty,timezone"`
	Theme             *Theme  `json:"theme,omitempty" validate:"omitempty,oneof=LIGHT DARK SYSTEM"`
	DateFormat        *string `json:"date_format,omitempty" validate:"omitempty,max=20"`
	Currency          *string `json:"currency,omitempty" validate:"omitempty,iso4217"`
	AccessibilityMode *bool   `json:"accessibility_mode,omitempty"`
	ReducedMotion     *bool   `json:"reduced_motion,omitempty"`
	HighContrast      *bool   `json:"high_contrast,omitempty"`
}

// NotificationPreferenceSummary is a lean summary for notification service
type NotificationPreferenceSummary struct {
	UserID              uuid.UUID                               `json:"user_id"`
	Channels            map[NotificationType][]NotificationChannel `json:"channels"`
	Timezone            string                                  `json:"timezone"`
	QuietHoursEnabled   bool                                    `json:"quiet_hours_enabled"`
}

// ToNotificationSummary converts preferences to a summary for notification service
func (p *Preference) ToNotificationSummary() *NotificationPreferenceSummary {
	channels := make(map[NotificationType][]NotificationChannel)
	hasQuietHours := false
	
	for notifType, setting := range p.NotificationSettings {
		if setting.Enabled {
			channels[notifType] = setting.Channels
		}
		if setting.Quiet != nil && setting.Quiet.Enabled {
			hasQuietHours = true
		}
	}
	
	return &NotificationPreferenceSummary{
		UserID:            p.UserID,
		Channels:          channels,
		Timezone:          p.UXPreferences.Timezone,
		QuietHoursEnabled: hasQuietHours,
	}
}

// GetFeatureFlag returns a feature flag value with a default
func (p *Preference) GetFeatureFlag(name string, defaultValue bool) bool {
	if val, ok := p.FeatureFlags[name]; ok {
		return val
	}
	return defaultValue
}

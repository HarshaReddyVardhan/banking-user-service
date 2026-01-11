package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Action represents an auditable action
type Action string

const (
	ActionCreate Action = "CREATE"
	ActionRead   Action = "READ"
	ActionUpdate Action = "UPDATE"
	ActionDelete Action = "DELETE"
	ActionAccess Action = "ACCESS" // For PII access by internal services
)

// ActorType represents who performed the action
type ActorType string

const (
	ActorUser    ActorType = "USER"
	ActorSystem  ActorType = "SYSTEM"
	ActorAdmin   ActorType = "ADMIN"
	ActorService ActorType = "SERVICE"
)

// Resource represents the type of resource being audited
type Resource string

const (
	ResourceProfile     Resource = "profile"
	ResourceAddress     Resource = "address"
	ResourceDevice      Resource = "device"
	ResourcePreference  Resource = "preference"
	ResourceKYCStatus   Resource = "kyc_status"
)

// AuditEvent represents an immutable audit event with HMAC signature
type AuditEvent struct {
	EventID       string    `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`
	UserID        string    `json:"user_id"`
	ActorID       string    `json:"actor_id"`
	ActorType     ActorType `json:"actor_type"`
	Action        Action    `json:"action"`
	Resource      Resource  `json:"resource"`
	ResourceID    string    `json:"resource_id,omitempty"`
	FieldsChanged []string  `json:"fields_changed,omitempty"` // Field names only, never values!
	IPHash        string    `json:"ip_hash"`                  // Hashed client IP
	RequestID     string    `json:"request_id"`               // End-to-end correlation
	ServiceName   string    `json:"service_name,omitempty"`   // For service-to-service calls
	Result        string    `json:"result"`                   // SUCCESS, FAILURE, DENIED
	FailureReason string    `json:"failure_reason,omitempty"`
	HMAC          string    `json:"hmac"`                     // Integrity signature
}

// AuditEventBuilder builds audit events with required fields
type AuditEventBuilder struct {
	event      *AuditEvent
	hmacSecret []byte
}

// NewAuditEvent creates a new audit event builder
func NewAuditEvent(hmacSecret []byte) *AuditEventBuilder {
	return &AuditEventBuilder{
		event: &AuditEvent{
			EventID:   uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Result:    "SUCCESS",
		},
		hmacSecret: hmacSecret,
	}
}

// UserID sets the user being affected
func (b *AuditEventBuilder) UserID(id string) *AuditEventBuilder {
	b.event.UserID = id
	return b
}

// Actor sets who performed the action
func (b *AuditEventBuilder) Actor(id string, actorType ActorType) *AuditEventBuilder {
	b.event.ActorID = id
	b.event.ActorType = actorType
	return b
}

// Action sets the action performed
func (b *AuditEventBuilder) Action(action Action) *AuditEventBuilder {
	b.event.Action = action
	return b
}

// Resource sets the resource type and ID
func (b *AuditEventBuilder) Resource(resource Resource, id string) *AuditEventBuilder {
	b.event.Resource = resource
	b.event.ResourceID = id
	return b
}

// FieldsChanged sets which fields were modified (names only!)
func (b *AuditEventBuilder) FieldsChanged(fields []string) *AuditEventBuilder {
	b.event.FieldsChanged = fields
	return b
}

// IPHash sets the hashed client IP
func (b *AuditEventBuilder) IPHash(hash string) *AuditEventBuilder {
	b.event.IPHash = hash
	return b
}

// RequestID sets the correlation ID
func (b *AuditEventBuilder) RequestID(id string) *AuditEventBuilder {
	b.event.RequestID = id
	return b
}

// Service sets the calling service name
func (b *AuditEventBuilder) Service(name string) *AuditEventBuilder {
	b.event.ServiceName = name
	return b
}

// Failure marks the event as a failure
func (b *AuditEventBuilder) Failure(reason string) *AuditEventBuilder {
	b.event.Result = "FAILURE"
	b.event.FailureReason = reason
	return b
}

// Denied marks the event as access denied
func (b *AuditEventBuilder) Denied(reason string) *AuditEventBuilder {
	b.event.Result = "DENIED"
	b.event.FailureReason = reason
	return b
}

// Build creates the final audit event with HMAC signature
func (b *AuditEventBuilder) Build() (*AuditEvent, error) {
	// Compute HMAC before returning
	signature, err := b.computeHMAC()
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC: %w", err)
	}
	b.event.HMAC = signature

	return b.event, nil
}

// computeHMAC creates HMAC-SHA256 signature of the event
func (b *AuditEventBuilder) computeHMAC() (string, error) {
	// Create a copy without HMAC field for signing
	eventCopy := *b.event
	eventCopy.HMAC = ""

	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, b.hmacSecret)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC verifies the integrity of an audit event
func VerifyHMAC(event *AuditEvent, hmacSecret []byte) bool {
	// Store original HMAC
	originalHMAC := event.HMAC

	// Create copy without HMAC for verification
	eventCopy := *event
	eventCopy.HMAC = ""

	data, err := json.Marshal(eventCopy)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(data)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(originalHMAC), []byte(expectedMAC))
}

// HashIP hashes an IP address for privacy
func HashIP(ip string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

// AuditEventJSON returns the event as JSON bytes
func (e *AuditEvent) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// ParseAuditEvent parses an audit event from JSON
func ParseAuditEvent(data []byte) (*AuditEvent, error) {
	var event AuditEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

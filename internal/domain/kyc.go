package domain

import (
	"time"

	"github.com/google/uuid"
)

// KYCRejectionReason represents high-level rejection reasons
// Never contain actual document details
type KYCRejectionReason string

const (
	KYCRejectionDocumentExpired    KYCRejectionReason = "DOCUMENT_EXPIRED"
	KYCRejectionDocumentUnreadable KYCRejectionReason = "DOCUMENT_UNREADABLE"
	KYCRejectionDocumentMismatch   KYCRejectionReason = "DOCUMENT_MISMATCH"
	KYCRejectionSanctionMatch      KYCRejectionReason = "SANCTION_MATCH"
	KYCRejectionIncompleteInfo     KYCRejectionReason = "INCOMPLETE_INFO"
	KYCRejectionFraudSuspicion     KYCRejectionReason = "FRAUD_SUSPICION"
	KYCRejectionOther              KYCRejectionReason = "OTHER"
)

// KYCReference represents the KYC pointer (not document storage)
// This service does NOT store actual KYC documents!
type KYCReference struct {
	ReferenceID     uuid.UUID          `json:"reference_id"`     // ID in KYC service
	Status          KYCStatus          `json:"status"`
	RejectionReason *KYCRejectionReason `json:"rejection_reason,omitempty"`
	ExpiresAt       *time.Time         `json:"expires_at,omitempty"`
	VerifiedAt      *time.Time         `json:"verified_at,omitempty"`
	LastCheckedAt   time.Time          `json:"last_checked_at"`
}

// IsValid returns true if KYC is currently valid
func (k *KYCReference) IsValid() bool {
	if k.Status != KYCStatusApproved {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// NeedsReverification returns true if KYC needs rechecking
func (k *KYCReference) NeedsReverification(maxAge time.Duration) bool {
	return time.Since(k.LastCheckedAt) > maxAge
}

// KYCStatusResponse is the response for KYC status checks
type KYCStatusResponse struct {
	Status          KYCStatus           `json:"status"`
	RejectionReason *KYCRejectionReason `json:"rejection_reason,omitempty"`
	ExpiresAt       *time.Time          `json:"expires_at,omitempty"`
	CanPerformHighRisk bool             `json:"can_perform_high_risk"`
	Message         string              `json:"message,omitempty"`
}

// ToStatusResponse converts a KYCReference to a status response
func (k *KYCReference) ToStatusResponse() *KYCStatusResponse {
	response := &KYCStatusResponse{
		Status:          k.Status,
		RejectionReason: k.RejectionReason,
		ExpiresAt:       k.ExpiresAt,
		CanPerformHighRisk: k.IsValid(),
	}

	switch k.Status {
	case KYCStatusPending:
		response.Message = "Your identity verification is pending review."
	case KYCStatusApproved:
		if k.ExpiresAt != nil && time.Until(*k.ExpiresAt) < 30*24*time.Hour {
			response.Message = "Your verification will expire soon. Please renew."
		}
	case KYCStatusRejected:
		response.Message = "Your identity verification was not approved."
	case KYCStatusExpired:
		response.Message = "Your identity verification has expired. Please reverify."
	}

	return response
}

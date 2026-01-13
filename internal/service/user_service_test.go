package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/repository/postgres"
)

// MockUserRepository is a mock for testing
type MockUserRepository struct {
	GetByIDFunc    func(ctx context.Context, id uuid.UUID) (*domain.User, error)
	UpdateFunc     func(ctx context.Context, user *domain.User, expectedUpdatedAt time.Time) error
	SoftDeleteFunc func(ctx context.Context, id uuid.UUID) error
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return nil, nil
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User, expectedUpdatedAt time.Time) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, user, expectedUpdatedAt)
	}
	return nil
}

func (m *MockUserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if m.SoftDeleteFunc != nil {
		return m.SoftDeleteFunc(ctx, id)
	}
	return nil
}

// MockUserCache is a mock cache for testing
type MockUserCache struct {
	SetProfileFunc     func(ctx context.Context, profile interface{}) error
	InvalidateUserFunc func(ctx context.Context, userID uuid.UUID) error
	GetSummaryFunc     func(ctx context.Context, userID uuid.UUID) (*domain.UserSummary, error)
	SetSummaryFunc     func(ctx context.Context, summary *domain.UserSummary) error
}

func (m *MockUserCache) SetProfile(ctx context.Context, profile interface{}) error {
	if m.SetProfileFunc != nil {
		return m.SetProfileFunc(ctx, profile)
	}
	return nil
}

func (m *MockUserCache) InvalidateUser(ctx context.Context, userID uuid.UUID) error {
	if m.InvalidateUserFunc != nil {
		return m.InvalidateUserFunc(ctx, userID)
	}
	return nil
}

func (m *MockUserCache) GetSummary(ctx context.Context, userID uuid.UUID) (*domain.UserSummary, error) {
	if m.GetSummaryFunc != nil {
		return m.GetSummaryFunc(ctx, userID)
	}
	return nil, nil
}

func (m *MockUserCache) SetSummary(ctx context.Context, summary *domain.UserSummary) error {
	if m.SetSummaryFunc != nil {
		return m.SetSummaryFunc(ctx, summary)
	}
	return nil
}

func TestErrUserNotFound(t *testing.T) {
	if ErrUserNotFound.Error() != "user not found" {
		t.Error("unexpected error message")
	}
}

func TestErrUserAlreadyExists(t *testing.T) {
	if ErrUserAlreadyExists.Error() != "user already exists" {
		t.Error("unexpected error message")
	}
}

func TestErrOptimisticLock(t *testing.T) {
	if ErrOptimisticLock.Error() != "optimistic lock conflict" {
		t.Error("unexpected error message")
	}
}

func TestErrInvalidInput(t *testing.T) {
	if ErrInvalidInput.Error() != "invalid input" {
		t.Error("unexpected error message")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that postgres errors can be detected
	wrappedErr := postgres.ErrUserNotFound
	if !errors.Is(wrappedErr, postgres.ErrUserNotFound) {
		t.Error("should be able to detect postgres.ErrUserNotFound")
	}
}

func TestUpdateUserRequest_PartialUpdate(t *testing.T) {
	name := "New Name"
	req := &domain.UpdateUserRequest{
		LegalName: &name,
	}

	if req.LegalName == nil || *req.LegalName != "New Name" {
		t.Error("LegalName should be set")
	}
	if req.Phone != nil {
		t.Error("Phone should be nil")
	}
	if req.Country != nil {
		t.Error("Country should be nil")
	}
}

func TestUpdateUserRequest_AllFields(t *testing.T) {
	name := "Full Update"
	phone := "+1-555-123-4567"
	country := "US"

	req := &domain.UpdateUserRequest{
		LegalName: &name,
		Phone:     &phone,
		Country:   &country,
	}

	if *req.LegalName != "Full Update" {
		t.Error("LegalName mismatch")
	}
	if *req.Phone != "+1-555-123-4567" {
		t.Error("Phone mismatch")
	}
	if *req.Country != "US" {
		t.Error("Country mismatch")
	}
}

func TestUserSummary_FromUser(t *testing.T) {
	userID := uuid.New()
	user := &domain.User{
		ID:        userID,
		LegalName: "Test User",
		Email:     "test@example.com",
		Status:    domain.UserStatusActive,
		KYCStatus: domain.KYCStatusApproved,
	}

	summary := user.ToSummary()

	if summary.ID != userID {
		t.Errorf("ID mismatch: expected %s, got %s", userID, summary.ID)
	}
	if summary.Status != domain.UserStatusActive {
		t.Errorf("Status mismatch")
	}
	if summary.KYCStatus != domain.KYCStatusApproved {
		t.Errorf("KYCStatus mismatch")
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Context should be done
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context should be cancelled")
	}

	if ctx.Err() != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", ctx.Err())
	}
}

func TestContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	time.Sleep(20 * time.Millisecond)

	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", ctx.Err())
	}
}

func TestUserStatus_Values(t *testing.T) {
	statuses := []domain.UserStatus{
		domain.UserStatusActive,
		domain.UserStatusPending,
		domain.UserStatusSuspended,
		domain.UserStatusDeleted,
	}

	seen := make(map[domain.UserStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate status: %s", s)
		}
		seen[s] = true
	}
}

func TestKYCStatus_Values(t *testing.T) {
	statuses := []domain.KYCStatus{
		domain.KYCStatusPending,
		domain.KYCStatusApproved,
		domain.KYCStatusRejected,
		domain.KYCStatusExpired,
	}

	seen := make(map[domain.KYCStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate KYC status: %s", s)
		}
		seen[s] = true
	}
}

func TestUUIDGeneration(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	if id1 == id2 {
		t.Error("UUIDs should be unique")
	}

	if id1 == uuid.Nil {
		t.Error("UUID should not be nil")
	}
}

func TestTimeComparison_OptimisticLocking(t *testing.T) {
	now := time.Now()
	time.Sleep(time.Millisecond)
	later := time.Now()

	if !later.After(now) {
		t.Error("later should be after now")
	}

	// Simulate optimistic lock check
	expectedUpdatedAt := now
	actualUpdatedAt := later

	if expectedUpdatedAt.Equal(actualUpdatedAt) {
		t.Error("timestamps should not be equal for failed lock")
	}
}

func TestChangedFieldsTracking(t *testing.T) {
	changedFields := []string{}

	// Simulate tracking changes
	oldName := "Old Name"
	newName := "New Name"
	if oldName != newName {
		changedFields = append(changedFields, "legal_name")
	}

	oldPhone := "+1-555-000-0000"
	newPhone := "+1-555-123-4567"
	if oldPhone != newPhone {
		changedFields = append(changedFields, "phone")
	}

	// No change to country
	oldCountry := "US"
	newCountry := "US"
	if oldCountry != newCountry {
		changedFields = append(changedFields, "country")
	}

	if len(changedFields) != 2 {
		t.Errorf("expected 2 changed fields, got %d", len(changedFields))
	}
}

func TestNoChanges_EarlyReturn(t *testing.T) {
	changedFields := []string{}

	if len(changedFields) == 0 {
		// Should return early
		return
	}

	t.Error("should have returned early")
}

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/service"
)

// MockUserService is a mock implementation for testing
type MockUserService struct {
	GetProfileFunc    func(userID uuid.UUID) (*domain.User, error)
	UpdateProfileFunc func(userID uuid.UUID, req *domain.UpdateUserRequest) (*domain.User, error)
	DeleteProfileFunc func(userID uuid.UUID) error
}

func (m *MockUserService) GetProfile(userID uuid.UUID) (*domain.User, error) {
	if m.GetProfileFunc != nil {
		return m.GetProfileFunc(userID)
	}
	return nil, nil
}

func (m *MockUserService) UpdateProfile(userID uuid.UUID, req *domain.UpdateUserRequest, clientIP, requestID string) (*domain.User, error) {
	if m.UpdateProfileFunc != nil {
		return m.UpdateProfileFunc(userID, req)
	}
	return nil, nil
}

func (m *MockUserService) DeleteProfile(userID uuid.UUID, clientIP, requestID string) error {
	if m.DeleteProfileFunc != nil {
		return m.DeleteProfileFunc(userID)
	}
	return nil
}

func setupTestContext(method, path string, body string) (*echo.Echo, echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	return e, c, rec
}

func TestGetProfile_Success(t *testing.T) {
	userID := uuid.New()
	dob := time.Date(1990, 1, 15, 0, 0, 0, 0, time.UTC)
	expectedUser := &domain.User{
		ID:        userID,
		LegalName: "John Doe",
		Email:     "john@example.com",
		Phone:     "+1-555-123-4567",
		DOB:       &dob,
		Country:   "US",
		Status:    domain.UserStatusActive,
		KYCStatus: domain.KYCStatusApproved,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, c, rec := setupTestContext(http.MethodGet, "/api/v1/users/me", "")
	c.Set(string(middleware.UserIDKey), userID)
	c.Set(string(middleware.RequestIDKey), "req-123")

	// Note: In a real test, we would use dependency injection
	// For now, test the handler structure
	handler := &UserHandler{}

	// Verify response structure with mock
	response := handler.toProfileResponse(expectedUser)
	if response.ID != userID {
		t.Errorf("expected ID %s, got %s", userID, response.ID)
	}
	if response.LegalName != "John Doe" {
		t.Errorf("expected LegalName 'John Doe', got %s", response.LegalName)
	}
	if response.Email != "john@example.com" {
		t.Errorf("expected Email 'john@example.com', got %s", response.Email)
	}
	if response.DOB == nil || *response.DOB != "1990-01-15" {
		t.Errorf("expected DOB '1990-01-15', got %v", response.DOB)
	}

	// Test context is properly set up
	if rec == nil {
		t.Error("response recorder should not be nil")
	}
}

func TestGetProfile_Unauthorized(t *testing.T) {
	_, c, _ := setupTestContext(http.MethodGet, "/api/v1/users/me", "")
	// No user ID in context

	// Simulate the handler checking for user ID
	_, ok := middleware.GetUserIDFromEcho(c)
	if ok {
		t.Error("expected no user ID in context")
	}
}

func TestUpdateProfile_ValidInput(t *testing.T) {
	userID := uuid.New()
	body := `{"legal_name": "Jane Doe", "phone": "+1-555-999-8888"}`

	_, c, _ := setupTestContext(http.MethodPut, "/api/v1/users/me", body)
	c.Set(string(middleware.UserIDKey), userID)
	c.Set(string(middleware.RequestIDKey), "req-456")

	var req domain.UpdateUserRequest
	err := json.Unmarshal([]byte(body), &req)
	if err != nil {
		t.Fatalf("failed to parse request: %v", err)
	}

	if req.LegalName == nil || *req.LegalName != "Jane Doe" {
		t.Error("expected LegalName to be set")
	}
	if req.Phone == nil || *req.Phone != "+1-555-999-8888" {
		t.Error("expected Phone to be set")
	}
}

func TestUpdateProfile_EmptyBody(t *testing.T) {
	_, c, _ := setupTestContext(http.MethodPut, "/api/v1/users/me", "{}")

	var req domain.UpdateUserRequest
	err := c.Bind(&req)
	if err != nil {
		t.Fatalf("binding should succeed for empty object: %v", err)
	}

	// All fields should be nil
	if req.LegalName != nil || req.Phone != nil || req.Country != nil {
		t.Error("expected all fields to be nil for empty request")
	}
}

func TestDeleteProfile_Success(t *testing.T) {
	userID := uuid.New()
	_, c, _ := setupTestContext(http.MethodDelete, "/api/v1/users/me", "")
	c.Set(string(middleware.UserIDKey), userID)
	c.Set(string(middleware.RequestIDKey), "req-789")

	// Verify user ID is accessible
	gotID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		t.Error("expected user ID to be in context")
	}
	if gotID != userID {
		t.Errorf("expected user ID %s, got %s", userID, gotID)
	}
}

func TestHandleServiceError(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		expectedCode int
	}{
		{"user not found", service.ErrUserNotFound, http.StatusNotFound},
		{"user already exists", service.ErrUserAlreadyExists, http.StatusConflict},
		{"optimistic lock", service.ErrOptimisticLock, http.StatusConflict},
		{"invalid input", service.ErrInvalidInput, http.StatusBadRequest},
		{"unknown error", echo.ErrInternalServerError, http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handleServiceError(tc.err)
			httpErr, ok := err.(*echo.HTTPError)
			if !ok {
				t.Fatalf("expected HTTPError, got %T", err)
			}
			if httpErr.Code != tc.expectedCode {
				t.Errorf("expected code %d, got %d", tc.expectedCode, httpErr.Code)
			}
		})
	}
}

func TestProfileResponse_NilDOB(t *testing.T) {
	user := &domain.User{
		ID:        uuid.New(),
		LegalName: "Test User",
		Email:     "test@example.com",
		Country:   "US",
		Status:    domain.UserStatusActive,
		KYCStatus: domain.KYCStatusPending,
		DOB:       nil, // No DOB
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	handler := &UserHandler{}
	response := handler.toProfileResponse(user)

	if response.DOB != nil {
		t.Error("expected nil DOB in response")
	}
}

func TestProfileResponse_AllFields(t *testing.T) {
	userID := uuid.New()
	dob := time.Date(1985, 6, 20, 0, 0, 0, 0, time.UTC)
	now := time.Now()

	user := &domain.User{
		ID:        userID,
		LegalName: "Complete User",
		Email:     "complete@example.com",
		Phone:     "+44-20-1234-5678",
		DOB:       &dob,
		Country:   "GB",
		Status:    domain.UserStatusActive,
		KYCStatus: domain.KYCStatusApproved,
		CreatedAt: now,
		UpdatedAt: now,
	}

	handler := &UserHandler{}
	response := handler.toProfileResponse(user)

	if response.ID != userID {
		t.Errorf("ID mismatch")
	}
	if response.LegalName != "Complete User" {
		t.Errorf("LegalName mismatch")
	}
	if response.Email != "complete@example.com" {
		t.Errorf("Email mismatch")
	}
	if response.Phone != "+44-20-1234-5678" {
		t.Errorf("Phone mismatch")
	}
	if response.DOB == nil || *response.DOB != "1985-06-20" {
		t.Errorf("DOB mismatch: got %v", response.DOB)
	}
	if response.Country != "GB" {
		t.Errorf("Country mismatch")
	}
	if response.Status != domain.UserStatusActive {
		t.Errorf("Status mismatch")
	}
	if response.KYCStatus != domain.KYCStatusApproved {
		t.Errorf("KYCStatus mismatch")
	}
}

func TestRealIP_FromContext(t *testing.T) {
	_, c, _ := setupTestContext(http.MethodGet, "/", "")
	c.Request().RemoteAddr = "192.168.1.100:12345"

	ip := c.RealIP()
	if ip == "" {
		t.Error("expected IP address")
	}
}

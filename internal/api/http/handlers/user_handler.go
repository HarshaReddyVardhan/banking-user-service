package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/service"
)

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	userService *service.UserService
	log         *logger.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *service.UserService, log *logger.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		log:         log.Named("user_handler"),
	}
}

// ProfileResponse is the response for profile endpoints
type ProfileResponse struct {
	ID        uuid.UUID          `json:"id"`
	LegalName string             `json:"legal_name"`
	Email     string             `json:"email"`
	Phone     string             `json:"phone,omitempty"`
	DOB       *string            `json:"dob,omitempty"`
	Country   string             `json:"country"`
	Status    domain.UserStatus  `json:"status"`
	KYCStatus domain.KYCStatus   `json:"kyc_status"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// GetProfile handles GET /api/v1/users/me
func (h *UserHandler) GetProfile(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	// Get authenticated user ID
	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	// Get profile
	user, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to get profile",
			logger.RequestID(requestID),
			logger.UserID(userID.String()),
			logger.ErrorField(err),
		)
		return handleServiceError(err)
	}

	// Convert to response (hide internal fields)
	response := h.toProfileResponse(user)
	return c.JSON(http.StatusOK, response)
}

// UpdateProfile handles PUT /api/v1/users/me
func (h *UserHandler) UpdateProfile(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	// Get authenticated user ID
	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	// Parse request body
	var req domain.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	// Validate request
	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Get client IP for audit
	clientIP := c.RealIP()

	// Update profile
	user, err := h.userService.UpdateProfile(ctx, userID, &req, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to update profile",
			logger.RequestID(requestID),
			logger.UserID(userID.String()),
			logger.ErrorField(err),
		)
		return handleServiceError(err)
	}

	// Convert to response
	response := h.toProfileResponse(user)
	return c.JSON(http.StatusOK, response)
}

// DeleteProfile handles DELETE /api/v1/users/me (soft delete)
func (h *UserHandler) DeleteProfile(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	// Get authenticated user ID
	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	// Get client IP for audit
	clientIP := c.RealIP()

	// Delete profile (soft delete)
	err := h.userService.DeleteProfile(ctx, userID, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to delete profile",
			logger.RequestID(requestID),
			logger.UserID(userID.String()),
			logger.ErrorField(err),
		)
		return handleServiceError(err)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *UserHandler) toProfileResponse(user *domain.User) *ProfileResponse {
	resp := &ProfileResponse{
		ID:        user.ID,
		LegalName: user.LegalName,
		Email:     user.Email,
		Phone:     user.Phone,
		Country:   user.Country,
		Status:    user.Status,
		KYCStatus: user.KYCStatus,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	if user.DOB != nil {
		dob := user.DOB.Format("2006-01-02")
		resp.DOB = &dob
	}

	return resp
}

// handleServiceError converts service errors to HTTP errors
func handleServiceError(err error) error {
	switch err {
	case service.ErrUserNotFound:
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	case service.ErrUserAlreadyExists:
		return echo.NewHTTPError(http.StatusConflict, "user already exists")
	case service.ErrOptimisticLock:
		return echo.NewHTTPError(http.StatusConflict, "resource was modified, please retry")
	case service.ErrInvalidInput:
		return echo.NewHTTPError(http.StatusBadRequest, "invalid input")
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, "internal server error")
	}
}

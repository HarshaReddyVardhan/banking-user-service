package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/service"
)

// PreferenceHandler handles preference-related HTTP requests
type PreferenceHandler struct {
	prefService *service.PreferenceService
	log         *logger.Logger
}

// NewPreferenceHandler creates a new preference handler
func NewPreferenceHandler(prefService *service.PreferenceService, log *logger.Logger) *PreferenceHandler {
	return &PreferenceHandler{
		prefService: prefService,
		log:         log.Named("preference_handler"),
	}
}

// GetPreferences handles GET /api/v1/users/me/preferences
func (h *PreferenceHandler) GetPreferences(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	prefs, err := h.prefService.GetPreferences(ctx, userID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to get preferences", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, prefs)
}

// UpdatePreferences handles PUT /api/v1/users/me/preferences
func (h *PreferenceHandler) UpdatePreferences(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	var req domain.UpdateUXPreferencesRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	clientIP := c.RealIP()

	prefs, err := h.prefService.UpdateUXPreferences(ctx, userID, &req, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to update preferences", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, prefs)
}

// UpdateNotificationSettings handles PUT /api/v1/users/me/preferences/notifications
func (h *PreferenceHandler) UpdateNotificationSettings(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	var req domain.UpdateNotificationRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	clientIP := c.RealIP()

	prefs, err := h.prefService.UpdateNotificationSettings(ctx, userID, &req, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to update notification settings", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, prefs)
}

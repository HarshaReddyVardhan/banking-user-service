package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/service"
)

// DeviceHandler handles device-related HTTP requests
type DeviceHandler struct {
	deviceService *service.DeviceService
	log           *logger.Logger
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(deviceService *service.DeviceService, log *logger.Logger) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		log:           log.Named("device_handler"),
	}
}

// ListDevices handles GET /api/v1/users/me/devices
func (h *DeviceHandler) ListDevices(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	// Get current device fingerprint from header (if available)
	currentFingerprint := c.Request().Header.Get("X-Device-Fingerprint")

	devices, err := h.deviceService.ListDevices(ctx, userID, currentFingerprint)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to list devices", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, devices)
}

// RemoveDevice handles DELETE /api/v1/users/me/devices/:id
func (h *DeviceHandler) RemoveDevice(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	deviceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid device ID")
	}

	clientIP := c.RealIP()

	err = h.deviceService.RemoveDevice(ctx, userID, deviceID, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to remove device", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.NoContent(http.StatusNoContent)
}

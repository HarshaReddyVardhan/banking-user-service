package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/domain"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/service"
)

// AddressHandler handles address-related HTTP requests
type AddressHandler struct {
	addressService *service.AddressService
	log            *logger.Logger
}

// NewAddressHandler creates a new address handler
func NewAddressHandler(addressService *service.AddressService, log *logger.Logger) *AddressHandler {
	return &AddressHandler{
		addressService: addressService,
		log:            log.Named("address_handler"),
	}
}

// ListAddresses handles GET /api/v1/users/me/addresses
func (h *AddressHandler) ListAddresses(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	addresses, err := h.addressService.ListAddresses(ctx, userID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to list addresses", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, addresses)
}

// CreateAddress handles POST /api/v1/users/me/addresses
func (h *AddressHandler) CreateAddress(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	var req domain.CreateAddressRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	if err := c.Validate(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	clientIP := c.RealIP()

	address, err := h.addressService.CreateAddress(ctx, userID, &req, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to create address", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusCreated, address)
}

// GetAddress handles GET /api/v1/users/me/addresses/:id
func (h *AddressHandler) GetAddress(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	addressID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address ID")
	}

	address, err := h.addressService.GetAddress(ctx, userID, addressID)
	if err != nil {
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, address)
}

// UpdateAddress handles PUT /api/v1/users/me/addresses/:id
func (h *AddressHandler) UpdateAddress(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	addressID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address ID")
	}

	var req domain.UpdateAddressRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	clientIP := c.RealIP()

	address, err := h.addressService.UpdateAddress(ctx, userID, addressID, &req, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to update address", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.JSON(http.StatusOK, address)
}

// DeleteAddress handles DELETE /api/v1/users/me/addresses/:id
func (h *AddressHandler) DeleteAddress(c echo.Context) error {
	ctx := c.Request().Context()
	requestID := middleware.GetRequestIDFromEcho(c)

	userID, ok := middleware.GetUserIDFromEcho(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	addressID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address ID")
	}

	clientIP := c.RealIP()

	err = h.addressService.DeleteAddress(ctx, userID, addressID, clientIP, requestID)
	if err != nil {
		h.log.WithContext(ctx).Error("failed to delete address", logger.ErrorField(err))
		return handleServiceError(err)
	}

	return c.NoContent(http.StatusNoContent)
}

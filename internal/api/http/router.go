package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/banking/user-service/internal/api/http/handlers"
	"github.com/banking/user-service/internal/api/http/middleware"
	"github.com/banking/user-service/internal/config"
	"github.com/banking/user-service/internal/pkg/health"
	"github.com/banking/user-service/internal/pkg/logger"
	"github.com/banking/user-service/internal/pkg/validator"
	"github.com/banking/user-service/internal/resilience"
	"github.com/banking/user-service/internal/service"
)

// Router holds the Echo instance and dependencies
type Router struct {
	echo   *echo.Echo
	cfg    *config.Config
	log    *logger.Logger
	health *health.Health
}

// Dependencies for the router
type RouterDeps struct {
	Config         *config.Config
	Logger         *logger.Logger
	Health         *health.Health
	UserService    *service.UserService
	AddressService *service.AddressService
	DeviceService  *service.DeviceService
	PrefService    *service.PreferenceService
	RedisClient    *redis.Client
	CircuitBreaker *resilience.CircuitBreaker
	AuthPublicKey  interface{}
}

// NewRouter creates a new HTTP router with all middleware and routes
func NewRouter(deps RouterDeps) *Router {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Validator = validator.New()

	router := &Router{
		echo:   e,
		cfg:    deps.Config,
		log:    deps.Logger,
		health: deps.Health,
	}

	// Configure middleware
	router.setupMiddleware(deps)

	// Configure routes
	router.setupRoutes(deps)

	return router
}

func (r *Router) setupMiddleware(deps RouterDeps) {
	// Recovery middleware (first - catches panics)
	r.echo.Use(middleware.RecoveryLogging(deps.Logger))

	// Request ID middleware (second - needed for tracing)
	r.echo.Use(middleware.RequestID())

	// Logging middleware
	r.echo.Use(middleware.Logging(deps.Logger))

	// CORS middleware - SECURITY: Restrict origins in production
	// Empty AllowOrigins means no cross-origin requests allowed (most secure)
	// Configure specific origins via CORS_ALLOWED_ORIGINS environment variable
	allowedOrigins := deps.Config.GetCORSAllowedOrigins()
	r.echo.Use(echomiddleware.CORSWithConfig(echomiddleware.CORSConfig{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, middleware.RequestIDHeader},
		ExposeHeaders:    []string{middleware.RequestIDHeader, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
		AllowCredentials: true,
		MaxAge:           3600, // 1 hour preflight cache
	}))

	// Security headers - OWASP recommended configuration
	r.echo.Use(echomiddleware.SecureWithConfig(echomiddleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000, // 1 year
		HSTSPreloadEnabled:    true,
		HSTSExcludeSubdomains: false,
		ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	// Add custom security headers not covered by Echo's Secure middleware
	r.echo.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
			c.Response().Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Response().Header().Set("Pragma", "no-cache")
			return next(c)
		}
	})

	// Body limit
	r.echo.Use(echomiddleware.BodyLimit("1M"))

	// Timeout
	r.echo.Use(echomiddleware.TimeoutWithConfig(echomiddleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))
}

func (r *Router) setupRoutes(deps RouterDeps) {
	// Health check routes (no auth required)
	r.echo.GET("/health/live", echo.WrapHandler(http.HandlerFunc(deps.Health.LiveHandler())))
	r.echo.GET("/health/ready", echo.WrapHandler(http.HandlerFunc(deps.Health.ReadyHandler())))

	// Rate limiter
	rateLimiter := middleware.NewRateLimiter(deps.RedisClient, deps.CircuitBreaker, middleware.RateLimitConfig{
		PerUserPerMinute:       deps.Config.RateLimit.PerUserPerMinute,
		PerIPPerMinute:         deps.Config.RateLimit.PerIPPerMinute,
		ProfileUpdatesPerHour:  deps.Config.RateLimit.ProfileUpdatesPerHour,
		AddressChangesPerHour:  deps.Config.RateLimit.AddressChangesPerHour,
		BurstSize:              deps.Config.RateLimit.BurstSize,
		EnableInMemoryFallback: deps.Config.RateLimit.EnableInMemoryFallback,
	})

	// Auth middleware config
	authConfig := middleware.AuthConfig{
		PublicKey: deps.AuthPublicKey,
		Issuer:    deps.Config.Auth.JWTIssuer,
		Audiences: deps.Config.Auth.JWTAudience,
		SkipPaths: []string{"/health"},
	}

	// API v1 routes
	v1 := r.echo.Group("/api/v1")
	v1.Use(middleware.Auth(authConfig))
	v1.Use(rateLimiter.RateLimit())

	// User routes
	userHandler := handlers.NewUserHandler(deps.UserService, deps.Logger)
	users := v1.Group("/users")
	{
		// Self routes (current user)
		users.GET("/me", userHandler.GetProfile)
		users.PUT("/me", userHandler.UpdateProfile)
		users.DELETE("/me", userHandler.DeleteProfile)
	}

	// Address routes
	addressHandler := handlers.NewAddressHandler(deps.AddressService, deps.Logger)
	addresses := v1.Group("/users/me/addresses")
	{
		addresses.GET("", addressHandler.ListAddresses)
		addresses.POST("", addressHandler.CreateAddress)
		addresses.GET("/:id", addressHandler.GetAddress)
		addresses.PUT("/:id", addressHandler.UpdateAddress)
		addresses.DELETE("/:id", addressHandler.DeleteAddress)
	}

	// Device routes
	deviceHandler := handlers.NewDeviceHandler(deps.DeviceService, deps.Logger)
	devices := v1.Group("/users/me/devices")
	{
		devices.GET("", deviceHandler.ListDevices)
		devices.DELETE("/:id", deviceHandler.RemoveDevice)
	}

	// Preference routes
	prefHandler := handlers.NewPreferenceHandler(deps.PrefService, deps.Logger)
	prefs := v1.Group("/users/me/preferences")
	{
		prefs.GET("", prefHandler.GetPreferences)
		prefs.PUT("", prefHandler.UpdatePreferences)
		prefs.PUT("/notifications", prefHandler.UpdateNotificationSettings)
	}
}

// Start starts the HTTP server
func (r *Router) Start() error {
	addr := fmt.Sprintf("%s:%d", r.cfg.Server.Host, r.cfg.Server.Port)
	r.log.Info("Starting HTTP server", logger.Component("http"), logger.Operation("start"))
	return r.echo.Start(addr)
}

// StartWithAddr starts the HTTP server on a specific address
func (r *Router) StartWithAddr(addr string) error {
	r.log.Info("Starting HTTP server on " + addr)
	return r.echo.Start(addr)
}

// Shutdown gracefully shuts down the server
func (r *Router) Shutdown(ctx context.Context) error {
	return r.echo.Shutdown(ctx)
}

// Echo returns the underlying Echo instance
func (r *Router) Echo() *echo.Echo {
	return r.echo
}

package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
)

// SetupCORS configures CORS middleware for Fiber
func SetupCORS() fiber.Handler {
	return cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,http://localhost:8080,https://yourdomain.com",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With,X-Organization-ID",
		AllowCredentials: true,
		ExposeHeaders:    "Content-Length,Access-Control-Allow-Origin,Access-Control-Allow-Headers",
		MaxAge:           int(12 * time.Hour),
	})
}

// SetupLogger configures logging middleware for Fiber
func SetupLogger() fiber.Handler {
	return logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} ${path} | ${error}\n",
		TimeFormat: "2006-01-02 15:04:05",
		TimeZone:   "Local",
		Done: func(c *fiber.Ctx, logString []byte) {
			// Custom logic after logging (e.g., send to external logging service)
			// This can be used to integrate with structured logging libraries
		},
	})
}

// SetupRecover configures panic recovery middleware for Fiber
func SetupRecover() fiber.Handler {
	return recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			// Custom panic handler - log to your preferred logging service
			// In production, you might want to log to external services
		},
	})
}

// SetupRequestID adds unique request ID to each request
func SetupRequestID() fiber.Handler {
	return requestid.New(requestid.Config{
		Header: "X-Request-ID",
		Generator: func() string {
			// Use github.com/google/uuid for UUID generation
			return uuid.New().String()
		},
	})
}

// SetupRateLimit configures rate limiting middleware
func SetupRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        100,             // Max 100 requests
		Expiration: 1 * time.Minute, // Per minute
		KeyGenerator: func(c *fiber.Ctx) string {
			// Rate limit per IP
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":       "Rate limit exceeded",
				"retry_after": "1 minute",
			})
		},
		SkipFailedRequests:     true,
		SkipSuccessfulRequests: false,
		Storage:                nil, // Use in-memory storage, consider Redis for production
	})
}

// SetupHelmet configures security headers middleware
func SetupHelmet() fiber.Handler {
	return helmet.New(helmet.Config{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		ContentSecurityPolicy: "default-src 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	})
}

// SetupAuthRateLimit configures stricter rate limiting for auth endpoints
func SetupAuthRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        10,               // Max 10 requests
		Expiration: 15 * time.Minute, // Per 15 minutes
		KeyGenerator: func(c *fiber.Ctx) string {
			// Rate limit auth endpoints per IP
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":       "Too many authentication attempts",
				"retry_after": "15 minutes",
			})
		},
		SkipFailedRequests:     false,
		SkipSuccessfulRequests: true, // Only count failed attempts
	})
}

// SetupJSONValidation ensures content-type is application/json for POST/PUT requests
func SetupJSONValidation() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Method() == "POST" || c.Method() == "PUT" || c.Method() == "PATCH" {
			if c.Get("Content-Type") != "application/json" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Content-Type must be application/json",
				})
			}
		}
		return c.Next()
	}
}

// SetupHealthCheck adds a simple health check endpoint
func SetupHealthCheck() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Path() == "/health" {
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"status":    "healthy",
				"timestamp": time.Now(),
				"uptime":    time.Since(time.Now()).String(), // This would be calculated from app start time
			})
		}
		return c.Next()
	}
}

// SetupCompression configures compression middleware
func SetupCompression() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Fiber has built-in compression via compress middleware
		// This is a placeholder for custom compression logic if needed
		return c.Next()
	}
}

// Config represents middleware configuration
type Config struct {
	EnableCORS        bool
	EnableLogger      bool
	EnableRecover     bool
	EnableRequestID   bool
	EnableRateLimit   bool
	EnableHelmet      bool
	EnableHealthCheck bool
	CORSOrigins       string
	RateLimitMax      int
	RateLimitDuration time.Duration
}

// DefaultConfig returns default middleware configuration
func DefaultConfig() Config {
	return Config{
		EnableCORS:        true,
		EnableLogger:      true,
		EnableRecover:     true,
		EnableRequestID:   true,
		EnableRateLimit:   true,
		EnableHelmet:      true,
		EnableHealthCheck: true,
		CORSOrigins:       "http://localhost:3000,http://localhost:8080",
		RateLimitMax:      100,
		RateLimitDuration: 1 * time.Minute,
	}
}

// SetupMiddlewares applies all configured middlewares to Fiber app
func SetupMiddlewares(app *fiber.App, config Config) {
	// Security headers - should be first
	if config.EnableHelmet {
		app.Use(SetupHelmet())
	}

	// Panic recovery - should be early
	if config.EnableRecover {
		app.Use(SetupRecover())
	}

	// Request ID - early for tracking
	if config.EnableRequestID {
		app.Use(SetupRequestID())
	}

	// CORS - before auth
	if config.EnableCORS {
		app.Use(SetupCORS())
	}

	// Logging - after request ID, before business logic
	if config.EnableLogger {
		app.Use(SetupLogger())
	}

	// Rate limiting - after logging
	if config.EnableRateLimit {
		app.Use(SetupRateLimit())
	}

	// Health check - simple endpoint
	if config.EnableHealthCheck {
		app.Use(SetupHealthCheck())
	}

	// JSON validation for API endpoints
	app.Use("/api/*", SetupJSONValidation())

	// Stricter rate limiting for auth endpoints
	app.Use("/api/auth/*", SetupAuthRateLimit())
}

// SetupProdMiddlewares applies production-ready middlewares
func SetupProdMiddlewares(app *fiber.App) {
	config := Config{
		EnableCORS:        true,
		EnableLogger:      true,
		EnableRecover:     true,
		EnableRequestID:   true,
		EnableRateLimit:   true,
		EnableHelmet:      true,
		EnableHealthCheck: true,
		CORSOrigins:       "https://yourdomain.com,https://app.yourdomain.com",
		RateLimitMax:      50,
		RateLimitDuration: 1 * time.Minute,
	}

	SetupMiddlewares(app, config)
}

// SetupDevMiddlewares applies development-friendly middlewares
func SetupDevMiddlewares(app *fiber.App) {
	config := Config{
		EnableCORS:        true,
		EnableLogger:      true,
		EnableRecover:     true,
		EnableRequestID:   true,
		EnableRateLimit:   false, // Disabled for easier testing
		EnableHelmet:      false, // Disabled for easier development
		EnableHealthCheck: true,
		CORSOrigins:       "*", // Allow all origins in development
		RateLimitMax:      1000,
		RateLimitDuration: 1 * time.Minute,
	}

	SetupMiddlewares(app, config)
}

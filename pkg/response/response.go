package response

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorInfo  `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// Meta represents metadata for paginated responses
type Meta struct {
	Page       int   `json:"page,omitempty"`
	Limit      int   `json:"limit,omitempty"`
	Total      int64 `json:"total,omitempty"`
	TotalPages int   `json:"total_pages,omitempty"`
}

// PaginatedData represents paginated data
type PaginatedData struct {
	Items interface{} `json:"items"`
	Meta  Meta        `json:"meta"`
}

// Success sends a successful response
func Success(c *fiber.Ctx, data interface{}, message ...string) error {
	msg := "Success"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// Created sends a 201 Created response
func Created(c *fiber.Ctx, data interface{}, message ...string) error {
	msg := "Resource created successfully"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// NoContent sends a 204 No Content response
func NoContent(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// BadRequest sends a 400 Bad Request response
func BadRequest(c *fiber.Ctx, message string, details ...interface{}) error {
	var detail interface{}
	if len(details) > 0 {
		detail = details[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "BAD_REQUEST",
			Message: message,
			Details: detail,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusBadRequest).JSON(response)
}

// Unauthorized sends a 401 Unauthorized response
func Unauthorized(c *fiber.Ctx, message ...string) error {
	msg := "Unauthorized"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "UNAUTHORIZED",
			Message: msg,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusUnauthorized).JSON(response)
}

// Forbidden sends a 403 Forbidden response
func Forbidden(c *fiber.Ctx, message ...string) error {
	msg := "Forbidden"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "FORBIDDEN",
			Message: msg,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusForbidden).JSON(response)
}

// NotFound sends a 404 Not Found response
func NotFound(c *fiber.Ctx, message ...string) error {
	msg := "Resource not found"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "NOT_FOUND",
			Message: msg,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusNotFound).JSON(response)
}

// Conflict sends a 409 Conflict response
func Conflict(c *fiber.Ctx, message string, details ...interface{}) error {
	var detail interface{}
	if len(details) > 0 {
		detail = details[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "CONFLICT",
			Message: message,
			Details: detail,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusConflict).JSON(response)
}

// UnprocessableEntity sends a 422 Unprocessable Entity response
func UnprocessableEntity(c *fiber.Ctx, message string, details ...interface{}) error {
	var detail interface{}
	if len(details) > 0 {
		detail = details[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "UNPROCESSABLE_ENTITY",
			Message: message,
			Details: detail,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusUnprocessableEntity).JSON(response)
}

// InternalServerError sends a 500 Internal Server Error response
func InternalServerError(c *fiber.Ctx, message ...string) error {
	msg := "Internal server error"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "INTERNAL_SERVER_ERROR",
			Message: msg,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusInternalServerError).JSON(response)
}

// ServiceUnavailable sends a 503 Service Unavailable response
func ServiceUnavailable(c *fiber.Ctx, message ...string) error {
	msg := "Service unavailable"
	if len(message) > 0 {
		msg = message[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "SERVICE_UNAVAILABLE",
			Message: msg,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusServiceUnavailable).JSON(response)
}

// Paginated sends a paginated response
func Paginated(c *fiber.Ctx, items interface{}, meta Meta, message ...string) error {
	msg := "Success"
	if len(message) > 0 {
		msg = message[0]
	}

	data := PaginatedData{
		Items: items,
		Meta:  meta,
	}

	response := APIResponse{
		Success:   true,
		Message:   msg,
		Data:      data,
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// ValidationError sends a validation error response
func ValidationError(c *fiber.Ctx, validationErrors interface{}) error {
	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    "VALIDATION_ERROR",
			Message: "Validation failed",
			Details: validationErrors,
		},
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusBadRequest).JSON(response)
}

// CustomError sends a custom error response
func CustomError(c *fiber.Ctx, statusCode int, code, message string, details ...interface{}) error {
	var detail interface{}
	if len(details) > 0 {
		detail = details[0]
	}

	response := APIResponse{
		Success: false,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
			Details: detail,
		},
		Timestamp: time.Now(),
	}

	return c.Status(statusCode).JSON(response)
}

// HealthCheck sends a health check response
func HealthCheck(c *fiber.Ctx, status string, details ...interface{}) error {
	data := map[string]interface{}{
		"status": status,
	}

	if len(details) > 0 {
		data["details"] = details[0]
	}

	response := APIResponse{
		Success:   true,
		Message:   "Health check",
		Data:      data,
		Timestamp: time.Now(),
	}

	statusCode := fiber.StatusOK
	if status != "healthy" {
		statusCode = fiber.StatusServiceUnavailable
	}

	return c.Status(statusCode).JSON(response)
}

// NewMeta creates pagination metadata
func NewMeta(page, limit int, total int64) Meta {
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages < 1 {
		totalPages = 1
	}

	return Meta{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
	}
}

// CalculateOffset calculates offset for pagination
func CalculateOffset(page, limit int) int {
	if page < 1 {
		page = 1
	}
	return (page - 1) * limit
}

// JWT Token response helpers

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// LoginSuccess sends a successful login response
func LoginSuccess(c *fiber.Ctx, accessToken, refreshToken string, expiresAt time.Time, user interface{}) error {
	expiresIn := time.Until(expiresAt).Seconds()

	data := map[string]interface{}{
		"token": TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(expiresIn),
			ExpiresAt:    expiresAt,
		},
		"user": user,
	}

	response := APIResponse{
		Success:   true,
		Message:   "Login successful",
		Data:      data,
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// RefreshSuccess sends a successful token refresh response
func RefreshSuccess(c *fiber.Ctx, accessToken string, expiresAt time.Time) error {
	expiresIn := time.Until(expiresAt).Seconds()

	data := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(expiresIn),
		ExpiresAt:   expiresAt,
	}

	response := APIResponse{
		Success:   true,
		Message:   "Token refreshed successfully",
		Data:      data,
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// LogoutSuccess sends a successful logout response
func LogoutSuccess(c *fiber.Ctx) error {
	response := APIResponse{
		Success:   true,
		Message:   "Logout successful",
		Timestamp: time.Now(),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// Error response helpers for specific domains

// UserNotFound sends user not found error
func UserNotFound(c *fiber.Ctx) error {
	return NotFound(c, "User not found")
}

// OrganizationNotFound sends organization not found error
func OrganizationNotFound(c *fiber.Ctx) error {
	return NotFound(c, "Organization not found")
}

// EmailAlreadyExists sends email already exists error
func EmailAlreadyExists(c *fiber.Ctx) error {
	return Conflict(c, "Email address already exists")
}

// InvalidCredentials sends invalid credentials error
func InvalidCredentials(c *fiber.Ctx) error {
	return Unauthorized(c, "Invalid email or password")
}

// InsufficientPermissions sends insufficient permissions error
func InsufficientPermissions(c *fiber.Ctx) error {
	return Forbidden(c, "Insufficient permissions to perform this action")
}

// ResourceAlreadyExists sends resource already exists error
func ResourceAlreadyExists(c *fiber.Ctx, resource string) error {
	return Conflict(c, resource+" already exists")
}

// InvalidToken sends invalid token error
func InvalidToken(c *fiber.Ctx) error {
	return Unauthorized(c, "Invalid or expired token")
}

// TokenExpired sends token expired error
func TokenExpired(c *fiber.Ctx) error {
	return Unauthorized(c, "Token has expired")
}

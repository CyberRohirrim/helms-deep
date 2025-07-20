package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

// Validator wraps the go-playground validator
type Validator struct {
	validate *validator.Validate
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Message)
	}
	return strings.Join(messages, "; ")
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	validate := validator.New()

	// Register custom validators
	validate.RegisterValidation("strong_password", validateStrongPassword)
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("organization_name", validateOrganizationName)

	return &Validator{
		validate: validate,
	}
}

// ValidateStruct validates a struct and returns validation errors
func (v *Validator) ValidateStruct(s interface{}) error {
	err := v.validate.Struct(s)
	if err == nil {
		return nil
	}

	validationErrors := ValidationErrors{}

	for _, err := range err.(validator.ValidationErrors) {
		validationError := ValidationError{
			Field: err.Field(),
			Tag:   err.Tag(),
			Value: fmt.Sprintf("%v", err.Value()),
		}

		// Create user-friendly error messages
		switch err.Tag() {
		case "required":
			validationError.Message = fmt.Sprintf("%s is required", err.Field())
		case "email":
			validationError.Message = fmt.Sprintf("%s must be a valid email address", err.Field())
		case "min":
			validationError.Message = fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
		case "max":
			validationError.Message = fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
		case "strong_password":
			validationError.Message = fmt.Sprintf("%s must contain at least 8 characters with uppercase, lowercase, number and special character", err.Field())
		case "username":
			validationError.Message = fmt.Sprintf("%s must contain only letters, numbers, and underscores", err.Field())
		case "organization_name":
			validationError.Message = fmt.Sprintf("%s must be a valid organization name", err.Field())
		case "oneof":
			validationError.Message = fmt.Sprintf("%s must be one of: %s", err.Field(), err.Param())
		default:
			validationError.Message = fmt.Sprintf("%s is invalid", err.Field())
		}

		validationErrors = append(validationErrors, validationError)
	}

	return validationErrors
}

// ValidateVar validates a single variable
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	return v.validate.Var(field, tag)
}

// Custom validation functions

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validateUsername validates username format
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	// Username should be 3-30 characters, alphanumeric and underscores only
	if len(username) < 3 || len(username) > 30 {
		return false
	}

	matched, _ := regexp.MatchString("^[a-zA-Z0-9_]+$", username)
	return matched
}

// validateOrganizationName validates organization name
func validateOrganizationName(fl validator.FieldLevel) bool {
	name := fl.Field().String()

	// Organization name should be 2-100 characters
	if len(name) < 2 || len(name) > 100 {
		return false
	}

	// Should not start or end with spaces
	if strings.TrimSpace(name) != name {
		return false
	}

	// Should contain at least one letter
	hasLetter := false
	for _, char := range name {
		if unicode.IsLetter(char) {
			hasLetter = true
			break
		}
	}

	return hasLetter
}

// Email validation
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// Password validation
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must be at most 128 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// Name validation
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}

	if len(name) < 2 {
		return fmt.Errorf("name must be at least 2 characters long")
	}

	if len(name) > 50 {
		return fmt.Errorf("name must be at most 50 characters long")
	}

	// Check if name contains only letters, spaces, hyphens, and apostrophes
	nameRegex := regexp.MustCompile(`^[a-zA-Z\s\-']+$`)
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("name can only contain letters, spaces, hyphens, and apostrophes")
	}

	return nil
}

// ID validation
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("ID is required")
	}

	if len(id) < 1 {
		return fmt.Errorf("ID cannot be empty")
	}

	if len(id) > 100 {
		return fmt.Errorf("ID is too long")
	}

	return nil
}

// Role validation
func ValidateRole(role string) error {
	validRoles := []string{"user", "admin"}

	for _, validRole := range validRoles {
		if role == validRole {
			return nil
		}
	}

	return fmt.Errorf("invalid role: %s. Valid roles are: %s", role, strings.Join(validRoles, ", "))
}

// Organization role validation
func ValidateOrganizationRole(role string) error {
	validRoles := []string{"owner", "admin", "member"}

	for _, validRole := range validRoles {
		if role == validRole {
			return nil
		}
	}

	return fmt.Errorf("invalid organization role: %s. Valid roles are: %s", role, strings.Join(validRoles, ", "))
}

// Pagination validation
func ValidatePagination(page, limit int) error {
	if page < 1 {
		return fmt.Errorf("page must be at least 1")
	}

	if limit < 1 {
		return fmt.Errorf("limit must be at least 1")
	}

	if limit > 100 {
		return fmt.Errorf("limit cannot exceed 100")
	}

	return nil
}

// Search term validation
func ValidateSearchTerm(term string) error {
	if len(term) < 2 {
		return fmt.Errorf("search term must be at least 2 characters long")
	}

	if len(term) > 100 {
		return fmt.Errorf("search term must be at most 100 characters long")
	}

	return nil
}

// UUID validation
func ValidateUUID(uuid string) error {
	if uuid == "" {
		return fmt.Errorf("UUID is required")
	}

	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(uuid) {
		return fmt.Errorf("invalid UUID format")
	}

	return nil
}

// Sanitize functions

// SanitizeString removes leading/trailing whitespace and normalizes spaces
func SanitizeString(s string) string {
	s = strings.TrimSpace(s)
	// Replace multiple consecutive spaces with single space
	spaceRegex := regexp.MustCompile(`\s+`)
	s = spaceRegex.ReplaceAllString(s, " ")
	return s
}

// SanitizeEmail normalizes email address
func SanitizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// SanitizeName normalizes name
func SanitizeName(name string) string {
	name = SanitizeString(name)
	// Capitalize first letter of each word
	words := strings.Fields(name)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

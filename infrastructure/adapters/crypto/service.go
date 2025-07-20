package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Service represents the crypto service
type Service struct {
	bcryptCost int
}

// Config holds crypto service configuration
type Config struct {
	BcryptCost int // bcrypt cost parameter (4-31, default 12)
}

// NewService creates a new crypto service
func NewService(config Config) *Service {
	cost := config.BcryptCost
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}

	return &Service{
		bcryptCost: cost,
	}
}

// HashPassword hashes a password using bcrypt
func (s *Service) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (s *Service) VerifyPassword(hashedPassword, password string) error {
	if hashedPassword == "" {
		return fmt.Errorf("hashed password cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return fmt.Errorf("password verification failed: %w", err)
	}

	return nil
}

// GenerateRandomBytes generates random bytes of specified length
func (s *Service) GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// GenerateRandomString generates a random base64 encoded string
func (s *Service) GenerateRandomString(length int) (string, error) {
	bytes, err := s.GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSalt generates a random salt for password hashing
func (s *Service) GenerateSalt() (string, error) {
	saltBytes, err := s.GenerateRandomBytes(32) // 32 bytes = 256 bits
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	return base64.URLEncoding.EncodeToString(saltBytes), nil
}

// HashPasswordWithSalt hashes a password with a custom salt using scrypt
func (s *Service) HashPasswordWithSalt(password, salt string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if salt == "" {
		return "", fmt.Errorf("salt cannot be empty")
	}

	saltBytes, err := base64.URLEncoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("invalid salt format: %w", err)
	}

	// scrypt parameters: N=32768, r=8, p=1, keyLen=32
	derivedKey, err := scrypt.Key([]byte(password), saltBytes, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %w", err)
	}

	return base64.URLEncoding.EncodeToString(derivedKey), nil
}

// VerifyPasswordWithSalt verifies a password against its scrypt hash
func (s *Service) VerifyPasswordWithSalt(password, salt, hash string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if salt == "" {
		return fmt.Errorf("salt cannot be empty")
	}
	if hash == "" {
		return fmt.Errorf("hash cannot be empty")
	}

	expectedHash, err := s.HashPasswordWithSalt(password, salt)
	if err != nil {
		return fmt.Errorf("failed to hash password for verification: %w", err)
	}

	if expectedHash != hash {
		return fmt.Errorf("password verification failed")
	}

	return nil
}

// GenerateAPIKey generates a random API key
func (s *Service) GenerateAPIKey() (string, error) {
	// Generate 32 random bytes for API key
	keyBytes, err := s.GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Prefix with "hd_" (helms-deep) and encode
	return fmt.Sprintf("hd_%s", base64.URLEncoding.EncodeToString(keyBytes)), nil
}

// ValidateAPIKey validates the format of an API key
func (s *Service) ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	if len(apiKey) < 10 { // Minimum reasonable length
		return fmt.Errorf("API key is too short")
	}

	// Check if it starts with expected prefix
	if len(apiKey) > 3 && apiKey[:3] == "hd_" {
		// Validate base64 part
		encodedPart := apiKey[3:]
		_, err := base64.URLEncoding.DecodeString(encodedPart)
		if err != nil {
			return fmt.Errorf("invalid API key format: %w", err)
		}
	}

	return nil
}

// GenerateSessionID generates a unique session ID
func (s *Service) GenerateSessionID() (string, error) {
	sessionBytes, err := s.GenerateRandomBytes(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	return base64.URLEncoding.EncodeToString(sessionBytes), nil
}

// HashData hashes arbitrary data using a simple hash function
func (s *Service) HashData(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}

	// Use a simple approach - in production, consider using SHA-256 or similar
	salt, err := s.GenerateSalt()
	if err != nil {
		return "", err
	}

	saltBytes, _ := base64.URLEncoding.DecodeString(salt)

	// Combine data with salt
	combined := append(data, saltBytes...)

	// Hash with scrypt
	hashedData, err := scrypt.Key(combined, saltBytes, 16384, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to hash data: %w", err)
	}

	// Return salt + hash encoded
	result := append(saltBytes, hashedData...)
	return base64.URLEncoding.EncodeToString(result), nil
}

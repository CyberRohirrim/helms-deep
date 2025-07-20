package domain

import (
	"context"
	"errors"
	"time"
)

// Token represents an authentication token
type Token struct {
	Value     string    `json:"value"`
	Type      TokenType `json:"type"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Claims represents JWT token claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

// Session represents a user session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	IsActive     bool      `json:"is_active"`
}

// LoginCredentials represents user login credentials
type LoginCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResult represents the result of a successful login
type LoginResult struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         UserInfo  `json:"user"`
}

// UserInfo represents basic user information for authentication
type UserInfo struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// NewToken creates a new token with validation
func NewToken(value string, tokenType TokenType, userID string, expiresAt time.Time) (*Token, error) {
	if value == "" {
		return nil, errors.New("token value cannot be empty")
	}
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	if expiresAt.Before(time.Now()) {
		return nil, errors.New("token cannot be expired")
	}

	return &Token{
		Value:     value,
		Type:      tokenType,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// IsExpired checks if the token is expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if the token is valid (not expired and has value)
func (t *Token) IsValid() bool {
	return t.Value != "" && !t.IsExpired()
}

// NewSession creates a new session
func NewSession(id, userID, accessToken, refreshToken string, expiresAt time.Time) (*Session, error) {
	if id == "" {
		return nil, errors.New("session ID cannot be empty")
	}
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	if accessToken == "" {
		return nil, errors.New("access token cannot be empty")
	}
	if refreshToken == "" {
		return nil, errors.New("refresh token cannot be empty")
	}

	now := time.Now()
	return &Session{
		ID:           id,
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		LastUsedAt:   now,
		IsActive:     true,
	}, nil
}

// UpdateLastUsed updates the last used timestamp
func (s *Session) UpdateLastUsed() {
	s.LastUsedAt = time.Now()
}

// Deactivate marks the session as inactive
func (s *Session) Deactivate() {
	s.IsActive = false
}

// IsExpired checks if the session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and active
func (s *Session) IsValid() bool {
	return s.IsActive && !s.IsExpired()
}

// NewLoginCredentials creates login credentials with validation
func NewLoginCredentials(email, password string) (*LoginCredentials, error) {
	if email == "" {
		return nil, errors.New("email cannot be empty")
	}
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	return &LoginCredentials{
		Email:    email,
		Password: password,
	}, nil
}

// TokenService defines the interface for token operations
type TokenService interface {
	// Generate a new access token
	GenerateAccessToken(userID, email, role string) (*Token, error)

	// Generate a new refresh token
	GenerateRefreshToken(userID string) (*Token, error)

	// Validate and parse token
	ValidateToken(tokenValue string) (*Claims, error)

	// Extract claims from token
	ExtractClaims(tokenValue string) (*Claims, error)

	// Check if token is blacklisted
	IsTokenBlacklisted(ctx context.Context, tokenValue string) (bool, error)

	// Blacklist a token
	BlacklistToken(ctx context.Context, tokenValue string, expiresAt time.Time) error
}

// SessionRepository defines the interface for session storage
type SessionRepository interface {
	// Create a new session
	Create(ctx context.Context, session *Session) error

	// Get session by ID
	GetByID(ctx context.Context, sessionID string) (*Session, error)

	// Get session by access token
	GetByAccessToken(ctx context.Context, accessToken string) (*Session, error)

	// Get session by refresh token
	GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error)

	// Update session
	Update(ctx context.Context, session *Session) error

	// Delete session
	Delete(ctx context.Context, sessionID string) error

	// Delete all sessions for a user
	DeleteByUserID(ctx context.Context, userID string) error

	// Get all active sessions for a user
	GetActiveByUserID(ctx context.Context, userID string) ([]*Session, error)
}

// AuthenticationService defines domain services for authentication
type AuthenticationService interface {
	// Authenticate user with credentials
	Authenticate(ctx context.Context, credentials *LoginCredentials) (*LoginResult, error)

	// Refresh access token using refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*LoginResult, error)

	// Logout user (invalidate session)
	Logout(ctx context.Context, accessToken string) error

	// Logout from all devices (invalidate all sessions)
	LogoutAll(ctx context.Context, userID string) error

	// Validate session
	ValidateSession(ctx context.Context, accessToken string) (*UserInfo, error)
}

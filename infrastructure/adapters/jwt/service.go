package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	authDomain "github.com/CyberRohirrim/helms-deep/internal/authentication/domain"
	"github.com/golang-jwt/jwt/v5"
)

// Service represents the JWT service
type Service struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	blacklist     BlacklistStore
}

// Config holds JWT service configuration
type Config struct {
	AccessSecret  string
	RefreshSecret string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

// BlacklistStore defines interface for token blacklisting
type BlacklistStore interface {
	IsBlacklisted(ctx context.Context, tokenValue string) (bool, error)
	Blacklist(ctx context.Context, tokenValue string, expiresAt time.Time) error
}

// CustomClaims represents custom JWT claims
type CustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Type   string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// NewService creates a new JWT service
func NewService(config Config, blacklist BlacklistStore) *Service {
	return &Service{
		accessSecret:  []byte(config.AccessSecret),
		refreshSecret: []byte(config.RefreshSecret),
		accessTTL:     config.AccessTTL,
		refreshTTL:    config.RefreshTTL,
		blacklist:     blacklist,
	}
}

// GenerateAccessToken generates a new access token
func (s *Service) GenerateAccessToken(userID, email, role string) (*authDomain.Token, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTTL)

	claims := CustomClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "helms-deep",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.accessSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return authDomain.NewToken(tokenString, authDomain.TokenTypeAccess, userID, expiresAt)
}

// GenerateRefreshToken generates a new refresh token
func (s *Service) GenerateRefreshToken(userID string) (*authDomain.Token, error) {
	now := time.Now()
	expiresAt := now.Add(s.refreshTTL)

	// Generate random ID for refresh token
	tokenID, err := generateRandomID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	claims := CustomClaims{
		UserID: userID,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "helms-deep",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return authDomain.NewToken(tokenString, authDomain.TokenTypeRefresh, userID, expiresAt)
}

// ValidateToken validates and parses a token
func (s *Service) ValidateToken(tokenValue string) (*authDomain.Claims, error) {
	// First try as access token
	claims, err := s.parseToken(tokenValue, s.accessSecret)
	if err != nil {
		// Try as refresh token
		claims, err = s.parseToken(tokenValue, s.refreshSecret)
		if err != nil {
			return nil, fmt.Errorf("invalid token: %w", err)
		}
	}

	// Check if token is blacklisted
	blacklisted, err := s.blacklist.IsBlacklisted(context.Background(), tokenValue)
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}
	if blacklisted {
		return nil, fmt.Errorf("token is blacklisted")
	}

	return &authDomain.Claims{
		UserID: claims.UserID,
		Email:  claims.Email,
		Role:   claims.Role,
		Exp:    claims.ExpiresAt.Unix(),
		Iat:    claims.IssuedAt.Unix(),
	}, nil
}

// ExtractClaims extracts claims from token without validation
func (s *Service) ExtractClaims(tokenValue string) (*authDomain.Claims, error) {
	// Parse without verification to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenValue, &CustomClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return &authDomain.Claims{
		UserID: claims.UserID,
		Email:  claims.Email,
		Role:   claims.Role,
		Exp:    claims.ExpiresAt.Unix(),
		Iat:    claims.IssuedAt.Unix(),
	}, nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *Service) IsTokenBlacklisted(ctx context.Context, tokenValue string) (bool, error) {
	return s.blacklist.IsBlacklisted(ctx, tokenValue)
}

// BlacklistToken adds a token to blacklist
func (s *Service) BlacklistToken(ctx context.Context, tokenValue string, expiresAt time.Time) error {
	return s.blacklist.Blacklist(ctx, tokenValue, expiresAt)
}

// parseToken parses and validates a token with given secret
func (s *Service) parseToken(tokenValue string, secret []byte) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenValue, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// generateRandomID generates a random ID for tokens
func generateRandomID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetTokenType determines if a token is access or refresh
func (s *Service) GetTokenType(tokenValue string) (authDomain.TokenType, error) {
	// Try to parse with access secret first
	_, err := s.parseToken(tokenValue, s.accessSecret)
	if err == nil {
		return authDomain.TokenTypeAccess, nil
	}

	// Try refresh secret
	_, err = s.parseToken(tokenValue, s.refreshSecret)
	if err == nil {
		return authDomain.TokenTypeRefresh, nil
	}

	return "", fmt.Errorf("unable to determine token type")
}

// RefreshAccessToken creates a new access token from a valid refresh token
func (s *Service) RefreshAccessToken(refreshTokenValue string) (*authDomain.Token, error) {
	// Validate refresh token
	claims, err := s.parseToken(refreshTokenValue, s.refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.Type != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Check if token is blacklisted
	blacklisted, err := s.blacklist.IsBlacklisted(context.Background(), refreshTokenValue)
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}
	if blacklisted {
		return nil, fmt.Errorf("refresh token is blacklisted")
	}

	// Generate new access token
	return s.GenerateAccessToken(claims.UserID, claims.Email, claims.Role)
}

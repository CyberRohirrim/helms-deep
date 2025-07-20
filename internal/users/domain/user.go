package domain

import (
	"context"
	"errors"
	"time"
)

// User represents the user domain entity
type User struct {
	ID           UserID    `json:"id"`
	Email        Email     `json:"email"`
	PasswordHash string    `json:"-"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserID value object
type UserID string

func NewUserID(id string) (UserID, error) {
	if id == "" {
		return "", errors.New("user ID cannot be empty")
	}
	return UserID(id), nil
}

func (id UserID) String() string {
	return string(id)
}

// Email value object
type Email string

func NewEmail(email string) (Email, error) {
	if email == "" {
		return "", errors.New("email cannot be empty")
	}
	// Add email validation logic here
	return Email(email), nil
}

func (e Email) String() string {
	return string(e)
}

// Role value object
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

func NewRole(role string) (Role, error) {
	switch role {
	case string(RoleUser), string(RoleAdmin):
		return Role(role), nil
	default:
		return "", errors.New("invalid role")
	}
}

func (r Role) String() string {
	return string(r)
}

func (r Role) IsAdmin() bool {
	return r == RoleAdmin
}

// NewUser creates a new user with validation
func NewUser(id, email, passwordHash, firstName, lastName, role string) (*User, error) {
	userID, err := NewUserID(id)
	if err != nil {
		return nil, err
	}

	userEmail, err := NewEmail(email)
	if err != nil {
		return nil, err
	}

	userRole, err := NewRole(role)
	if err != nil {
		return nil, err
	}

	if passwordHash == "" {
		return nil, errors.New("password hash cannot be empty")
	}

	if firstName == "" {
		return nil, errors.New("first name cannot be empty")
	}

	if lastName == "" {
		return nil, errors.New("last name cannot be empty")
	}

	return &User{
		ID:           userID,
		Email:        userEmail,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         userRole,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

// UpdateProfile updates user profile information
func (u *User) UpdateProfile(firstName, lastName string) error {
	if firstName == "" {
		return errors.New("first name cannot be empty")
	}
	if lastName == "" {
		return errors.New("last name cannot be empty")
	}

	u.FirstName = firstName
	u.LastName = lastName
	u.UpdatedAt = time.Now()

	return nil
}

// ChangeRole changes the user's role
func (u *User) ChangeRole(newRole string) error {
	role, err := NewRole(newRole)
	if err != nil {
		return err
	}

	u.Role = role
	u.UpdatedAt = time.Now()

	return nil
}

// UserRepository defines the interface for user data access
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email Email) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id UserID) error
	ExistsByEmail(ctx context.Context, email Email) (bool, error)
}

// UserService defines domain services for user operations
type UserService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(hashedPassword, password string) error
}

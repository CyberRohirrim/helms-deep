package domain

import (
	"context"
	"errors"
	"time"
)

// Organization represents the organization domain entity
type Organization struct {
	ID          OrganizationID `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	OwnerID     string         `json:"owner_id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// OrganizationID value object
type OrganizationID string

func NewOrganizationID(id string) (OrganizationID, error) {
	if id == "" {
		return "", errors.New("organization ID cannot be empty")
	}
	return OrganizationID(id), nil
}

func (id OrganizationID) String() string {
	return string(id)
}

// Member represents organization membership
type Member struct {
	OrganizationID OrganizationID `json:"organization_id"`
	UserID         string         `json:"user_id"`
	Role           MemberRole     `json:"role"`
	JoinedAt       time.Time      `json:"joined_at"`
}

// MemberRole value object
type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleAdmin  MemberRole = "admin"
	MemberRoleMember MemberRole = "member"
)

func NewMemberRole(role string) (MemberRole, error) {
	switch role {
	case string(MemberRoleOwner), string(MemberRoleAdmin), string(MemberRoleMember):
		return MemberRole(role), nil
	default:
		return "", errors.New("invalid member role")
	}
}

func (r MemberRole) String() string {
	return string(r)
}

func (r MemberRole) CanManageMembers() bool {
	return r == MemberRoleOwner || r == MemberRoleAdmin
}

func (r MemberRole) CanDeleteOrganization() bool {
	return r == MemberRoleOwner
}

// NewOrganization creates a new organization with validation
func NewOrganization(id, name, description, ownerID string) (*Organization, error) {
	orgID, err := NewOrganizationID(id)
	if err != nil {
		return nil, err
	}

	if name == "" {
		return nil, errors.New("organization name cannot be empty")
	}

	if ownerID == "" {
		return nil, errors.New("owner ID cannot be empty")
	}

	return &Organization{
		ID:          orgID,
		Name:        name,
		Description: description,
		OwnerID:     ownerID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

// UpdateInfo updates organization information
func (o *Organization) UpdateInfo(name, description string) error {
	if name == "" {
		return errors.New("organization name cannot be empty")
	}

	o.Name = name
	o.Description = description
	o.UpdatedAt = time.Now()

	return nil
}

// NewMember creates a new organization member
func NewMember(organizationID, userID, role string) (*Member, error) {
	orgID, err := NewOrganizationID(organizationID)
	if err != nil {
		return nil, err
	}

	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	memberRole, err := NewMemberRole(role)
	if err != nil {
		return nil, err
	}

	return &Member{
		OrganizationID: orgID,
		UserID:         userID,
		Role:           memberRole,
		JoinedAt:       time.Now(),
	}, nil
}

// ChangeRole changes member's role
func (m *Member) ChangeRole(newRole string) error {
	role, err := NewMemberRole(newRole)
	if err != nil {
		return err
	}

	m.Role = role
	return nil
}

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	Create(ctx context.Context, org *Organization) error
	GetByID(ctx context.Context, id OrganizationID) (*Organization, error)
	GetByOwner(ctx context.Context, ownerID string) ([]*Organization, error)
	Update(ctx context.Context, org *Organization) error
	Delete(ctx context.Context, id OrganizationID) error
	ExistsByName(ctx context.Context, name string) (bool, error)
}

// MemberRepository defines the interface for member data access
type MemberRepository interface {
	AddMember(ctx context.Context, member *Member) error
	RemoveMember(ctx context.Context, organizationID OrganizationID, userID string) error
	GetMembers(ctx context.Context, organizationID OrganizationID) ([]*Member, error)
	GetMember(ctx context.Context, organizationID OrganizationID, userID string) (*Member, error)
	UpdateMemberRole(ctx context.Context, organizationID OrganizationID, userID string, role MemberRole) error
	GetUserOrganizations(ctx context.Context, userID string) ([]*Member, error)
	IsMember(ctx context.Context, organizationID OrganizationID, userID string) (bool, error)
}

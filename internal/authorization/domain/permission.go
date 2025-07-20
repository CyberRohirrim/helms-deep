package domain

import (
	"context"
	"errors"
	"fmt"
)

// Permission represents a permission in the system
type Permission struct {
	Namespace string  `json:"namespace"`
	Object    string  `json:"object"`
	Relation  string  `json:"relation"`
	Subject   Subject `json:"subject"`
}

// Subject represents the subject of a permission (user or group)
type Subject struct {
	ID   string      `json:"id"`
	Type SubjectType `json:"type"`
}

// SubjectType represents the type of subject
type SubjectType string

const (
	SubjectTypeUser  SubjectType = "user"
	SubjectTypeGroup SubjectType = "group"
)

// Relation types for ReBAC
const (
	RelationOwner  = "owner"
	RelationAdmin  = "admin"
	RelationMember = "member"
	RelationViewer = "viewer"
	RelationEditor = "editor"
)

// Namespace types for ReBAC
const (
	NamespaceUsers         = "users"
	NamespaceOrganizations = "organizations"
	NamespaceRoles         = "roles"
	NamespaceResources     = "resources"
)

// NewPermission creates a new permission with validation
func NewPermission(namespace, object, relation string, subject Subject) (*Permission, error) {
	if namespace == "" {
		return nil, errors.New("namespace cannot be empty")
	}
	if object == "" {
		return nil, errors.New("object cannot be empty")
	}
	if relation == "" {
		return nil, errors.New("relation cannot be empty")
	}
	if subject.ID == "" {
		return nil, errors.New("subject ID cannot be empty")
	}

	return &Permission{
		Namespace: namespace,
		Object:    object,
		Relation:  relation,
		Subject:   subject,
	}, nil
}

// String returns the permission in Keto tuple format
func (p *Permission) String() string {
	return fmt.Sprintf("%s:%s#%s@%s", p.Namespace, p.Object, p.Relation, p.Subject.ID)
}

// NewSubject creates a new subject with validation
func NewSubject(id string, subjectType SubjectType) (Subject, error) {
	if id == "" {
		return Subject{}, errors.New("subject ID cannot be empty")
	}

	switch subjectType {
	case SubjectTypeUser, SubjectTypeGroup:
		return Subject{ID: id, Type: subjectType}, nil
	default:
		return Subject{}, errors.New("invalid subject type")
	}
}

// CheckRequest represents a permission check request
type CheckRequest struct {
	Namespace string  `json:"namespace"`
	Object    string  `json:"object"`
	Relation  string  `json:"relation"`
	Subject   Subject `json:"subject"`
}

// NewCheckRequest creates a new check request
func NewCheckRequest(namespace, object, relation, subjectID string, subjectType SubjectType) (*CheckRequest, error) {
	if namespace == "" {
		return nil, errors.New("namespace cannot be empty")
	}
	if object == "" {
		return nil, errors.New("object cannot be empty")
	}
	if relation == "" {
		return nil, errors.New("relation cannot be empty")
	}

	subject, err := NewSubject(subjectID, subjectType)
	if err != nil {
		return nil, err
	}

	return &CheckRequest{
		Namespace: namespace,
		Object:    object,
		Relation:  relation,
		Subject:   subject,
	}, nil
}

// ExpandResult represents the result of permission expansion
type ExpandResult struct {
	Tree *ExpandTree `json:"tree"`
}

// ExpandTree represents the tree structure of permission expansion
type ExpandTree struct {
	Type     string        `json:"type"`
	Subject  *Subject      `json:"subject,omitempty"`
	Children []*ExpandTree `json:"children,omitempty"`
}

// RelationTuple represents a Keto relation tuple
type RelationTuple struct {
	Namespace string  `json:"namespace"`
	Object    string  `json:"object"`
	Relation  string  `json:"relation"`
	Subject   Subject `json:"subject"`
}

// PermissionService defines the interface for permission operations
type PermissionService interface {
	// Check if a subject has permission to perform an action on an object
	Check(ctx context.Context, req *CheckRequest) (bool, error)

	// Create a permission relationship
	CreateRelation(ctx context.Context, permission *Permission) error

	// Delete a permission relationship
	DeleteRelation(ctx context.Context, permission *Permission) error

	// List all subjects that have a specific permission on an object
	Expand(ctx context.Context, namespace, object, relation string) (*ExpandResult, error)

	// List all objects a subject has specific permission on
	ListObjects(ctx context.Context, namespace, relation, subjectID string, subjectType SubjectType) ([]string, error)

	// List all permissions for a subject
	ListSubjectPermissions(ctx context.Context, subjectID string, subjectType SubjectType) ([]*Permission, error)
}

// AuthorizationRepository defines the interface for authorization data operations
type AuthorizationRepository interface {
	// Store permission assignment (for audit/history)
	StorePermissionAssignment(ctx context.Context, permission *Permission, assignedBy string) error

	// Get permission assignment history
	GetPermissionHistory(ctx context.Context, namespace, object, relation string) ([]*Permission, error)
}

// Helper functions for creating common permissions

// CreateUserResourcePermission creates a permission for a user on a resource
func CreateUserResourcePermission(namespace, objectID, relation, userID string) (*Permission, error) {
	subject, err := NewSubject(userID, SubjectTypeUser)
	if err != nil {
		return nil, err
	}

	return NewPermission(namespace, objectID, relation, subject)
}

// CreateRolePermission creates a role-based permission
func CreateRolePermission(role, userID string) (*Permission, error) {
	subject, err := NewSubject(userID, SubjectTypeUser)
	if err != nil {
		return nil, err
	}

	return NewPermission(NamespaceRoles, role, RelationMember, subject)
}

// CreateOrganizationMembershipPermission creates organization membership permission
func CreateOrganizationMembershipPermission(organizationID, userID, role string) (*Permission, error) {
	subject, err := NewSubject(userID, SubjectTypeUser)
	if err != nil {
		return nil, err
	}

	return NewPermission(NamespaceOrganizations, organizationID, role, subject)
}

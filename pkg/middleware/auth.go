package middleware

import (
	"strings"

	authDomain "github.com/CyberRohirrim/helms-deep/internal/authentication/domain"
	authzDomain "github.com/CyberRohirrim/helms-deep/internal/authorization/domain"
	"github.com/gofiber/fiber/v2"
)

// AuthMiddleware provides authentication and authorization middleware
type AuthMiddleware struct {
	tokenService      authDomain.TokenService
	permissionService authzDomain.PermissionService
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(tokenService authDomain.TokenService, permissionService authzDomain.PermissionService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService:      tokenService,
		permissionService: permissionService,
	}
}

// RequireAuth validates JWT token and sets user context
func (am *AuthMiddleware) RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := extractTokenFromHeader(c.Get("Authorization"))
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization token required",
			})
		}

		claims, err := am.tokenService.ValidateToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		// Set user context
		c.Locals("user_id", claims.UserID)
		c.Locals("user_email", claims.Email)
		c.Locals("user_role", claims.Role)
		c.Locals("claims", claims)

		return c.Next()
	}
}

// RequirePermission checks if user has permission for specific resource
func (am *AuthMiddleware) RequirePermission(namespace, relation string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := getUserID(c)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		// Extract object from path parameter or use a default
		object := c.Params("id")
		if object == "" {
			object = "*" // Allow access to general endpoints
		}

		// Create permission check request
		checkReq, err := authzDomain.NewCheckRequest(
			namespace,
			object,
			relation,
			userID,
			authzDomain.SubjectTypeUser,
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create permission check",
			})
		}

		// Check permission
		allowed, err := am.permissionService.Check(c.Context(), checkReq)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Permission check failed",
			})
		}

		if !allowed {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}

// RequireRole checks if user has specific role
func (am *AuthMiddleware) RequireRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRole := getUserRole(c)
		if userRole == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		if userRole != requiredRole {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient role",
			})
		}

		return c.Next()
	}
}

// RequireAdminRole checks if user has admin role
func (am *AuthMiddleware) RequireAdminRole() fiber.Handler {
	return am.RequireRole("admin")
}

// OptionalAuth validates token if present but doesn't require it
func (am *AuthMiddleware) OptionalAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := extractTokenFromHeader(c.Get("Authorization"))
		if token != "" {
			claims, err := am.tokenService.ValidateToken(token)
			if err == nil {
				// Set user context if token is valid
				c.Locals("user_id", claims.UserID)
				c.Locals("user_email", claims.Email)
				c.Locals("user_role", claims.Role)
				c.Locals("claims", claims)
			}
		}

		return c.Next()
	}
}

// RequireOwnership checks if user owns the resource
func (am *AuthMiddleware) RequireOwnership(namespace string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := getUserID(c)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		resourceID := c.Params("id")
		if resourceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Resource ID required",
			})
		}

		// Check ownership permission
		checkReq, err := authzDomain.NewCheckRequest(
			namespace,
			resourceID,
			authzDomain.RelationOwner,
			userID,
			authzDomain.SubjectTypeUser,
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create ownership check",
			})
		}

		allowed, err := am.permissionService.Check(c.Context(), checkReq)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Ownership check failed",
			})
		}

		if !allowed {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "You don't own this resource",
			})
		}

		return c.Next()
	}
}

// RequireOrganizationMember checks if user is member of organization
func (am *AuthMiddleware) RequireOrganizationMember() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := getUserID(c)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		organizationID := c.Params("org_id")
		if organizationID == "" {
			organizationID = c.Get("X-Organization-ID")
		}

		if organizationID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Organization ID required",
			})
		}

		// Check organization membership
		checkReq, err := authzDomain.NewCheckRequest(
			authzDomain.NamespaceOrganizations,
			organizationID,
			authzDomain.RelationMember,
			userID,
			authzDomain.SubjectTypeUser,
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create membership check",
			})
		}

		allowed, err := am.permissionService.Check(c.Context(), checkReq)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Membership check failed",
			})
		}

		if !allowed {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "You are not a member of this organization",
			})
		}

		// Set organization context
		c.Locals("organization_id", organizationID)

		return c.Next()
	}
}

// Helper functions

// extractTokenFromHeader extracts bearer token from Authorization header
func extractTokenFromHeader(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// getUserID gets user ID from context
func getUserID(c *fiber.Ctx) string {
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// getUserEmail gets user email from context
func getUserEmail(c *fiber.Ctx) string {
	if userEmail := c.Locals("user_email"); userEmail != nil {
		if email, ok := userEmail.(string); ok {
			return email
		}
	}
	return ""
}

// getUserRole gets user role from context
func getUserRole(c *fiber.Ctx) string {
	if userRole := c.Locals("user_role"); userRole != nil {
		if role, ok := userRole.(string); ok {
			return role
		}
	}
	return ""
}

// getClaims gets JWT claims from context
func getClaims(c *fiber.Ctx) *authDomain.Claims {
	if claims := c.Locals("claims"); claims != nil {
		if claimsObj, ok := claims.(*authDomain.Claims); ok {
			return claimsObj
		}
	}
	return nil
}

// IsAuthenticated checks if request is authenticated
func IsAuthenticated(c *fiber.Ctx) bool {
	return getUserID(c) != ""
}

// IsAdmin checks if user has admin role
func IsAdmin(c *fiber.Ctx) bool {
	return getUserRole(c) == "admin"
}

// GetUserContext returns user context information
func GetUserContext(c *fiber.Ctx) map[string]interface{} {
	return map[string]interface{}{
		"user_id":    getUserID(c),
		"user_email": getUserEmail(c),
		"user_role":  getUserRole(c),
		"claims":     getClaims(c),
	}
}

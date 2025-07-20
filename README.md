# Helms Deep Identity Service

A modern, scalable authentication and authorization service built with Go, implementing **Vertical Slice Architecture** and **ReBAC (Relationship-based Access Control)** using via **ory/keto** integration.

## Architecture

### 🏗️ Hybrid Architecture Approach
- **Vertical Slice Architecture**: Features organized by business capability, not technical layers
- **Hexagonal Architecture**: Clean separation between domain and infrastructure
- **Domain-Driven Design**: Bounded contexts for Authentication, Authorization, Users, and Organizations
- **ReBAC**: Relationship-based access control using Google Zanzibar patterns

### 📁 Project Structure
```
helms-deep/
├── cmd/server/              # Application entry point
├── internal/                # Private application code
│   ├── authentication/     # Authentication bounded context
│   │   ├── domain/         # Domain entities & interfaces
│   │   └── features/       # Vertical slices (login, refresh, logout)
│   ├── authorization/      # Authorization bounded context
│   │   ├── domain/         # Permission entities & ReBAC logic
│   │   └── features/       # Permission management features
│   ├── users/              # User management bounded context
│   │   ├── domain/         # User entities & business rules
│   │   └── features/       # User CRUD operations
│   └── organizations/      # Organization management
│       ├── domain/         # Organization entities
│       └── features/       # Organization & membership features
├── infrastructure/         # External concerns (Hexagonal Architecture)
│   ├── adapters/           # External service adapters
│   │   ├── keto/          # Ory Keto ReBAC client
│   │   ├── jwt/           # JWT token service
│   │   └── crypto/        # Cryptographic operations
│   ├── repositories/       # Database implementations
│   │   ├── user/          # User repository (PostgreSQL)
│   │   └── organization/  # Organization repository
│   └── database/          # Database connection & migrations
├── pkg/                    # Shared utilities (Cross-cutting concerns)
│   ├── middleware/        # HTTP middleware (auth, CORS, logging)
│   ├── validation/        # Input validation utilities
│   └── response/          # Standardized API responses
└── deployments/           # Infrastructure as Code
    ├── docker/            # Docker configurations
    ├── kubernetes/        # K8s manifests
    └── keto/             # Keto configuration & policies
```

## 🚀 Features

### Authentication
- **JWT-based Authentication**: Secure token-based authentication with access/refresh tokens
- **Session Management**: Stateless session management with token blacklisting
- **Password Security**: bcrypt hashing with configurable cost parameters
- **Token Validation**: Comprehensive token validation and parsing

### Authorization (ReBAC with ory/keto)
- **Relationship-based Access Control**: Fine-grained permissions using Google Zanzibar principles
- **Resource Ownership**: User ownership of resources with inheritance
- **Organization Membership**: Role-based access within organizations
- **Permission Inheritance**: Hierarchical permission structures
- **Real-time Permission Checks**: Millisecond-level permission validation

### User Management
- **User Registration**: Secure user account creation with validation
- **Profile Management**: User profile updates with domain validation
- **Role Management**: User role assignment and validation
- **Email Uniqueness**: Enforced unique email addresses

### Organization Management
- **Multi-tenancy**: Organization-based multi-tenant architecture
- **Membership Management**: Add/remove organization members
- **Role-based Access**: Owner, Admin, Member roles within organizations
- **Resource Isolation**: Organization-scoped resource access

### Technical Features
- **High Performance**: Fiber v2 - Express.js-inspired, built on fasthttp (10x faster than net/http)
- **Database**: PostgreSQL with connection pooling (pgx)
- **Validation**: Comprehensive input validation with custom rules
- **Error Handling**: Standardized error responses with detailed messaging
- **Middleware Stack**: Built-in CORS, Rate Limiting, Security Headers, Recovery, Logging
- **Health Checks**: Application and database health monitoring
- **Security**: Helmet security headers, request ID tracking, panic recovery
- **Rate Limiting**: Configurable rate limits per IP/endpoint with Redis support

## 🛠️ Technology Stack

- **Language**: Go 1.21+
- **Web Framework**: Fiber v2 (Express.js-inspired, ultra-fast HTTP framework)
- **Database**: PostgreSQL with pgx/pgxpool
- **Authorization**: ory/keto (Google Zanzibar implementation)
- **Authentication**: JWT with golang-jwt/jwt
- **Validation**: go-playground/validator with custom rules
- **Cryptography**: bcrypt + scrypt for password hashing
- **UUID**: google/uuid for unique identifiers
- **Middleware**: Built-in CORS, Rate Limiting, Security Headers, Logging

## 🏃‍♂️ Quick Start

### Prerequisites
- Go 1.21+
- PostgreSQL 14+
- ory/keto server

### Installation

1. Clone the repository:
```bash
git clone https://github.com/CyberRohirrim/helms-deep.git
cd helms-deep
```

2. Install dependencies:
```bash
go mod tidy
```

3. Set up environment variables:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=postgres
export DB_PASSWORD=password
export DB_NAME=helms_deep
export KETO_READ_URL=http://localhost:4466
export KETO_WRITE_URL=http://localhost:4467
export JWT_ACCESS_SECRET=your-access-secret
export JWT_REFRESH_SECRET=your-refresh-secret
```

4. Run database migrations:
```bash
# Setup PostgreSQL database first
createdb helms_deep
```

5. Start ory/keto server:
```bash
# Using Docker
docker run --rm -p 4466:4466 -p 4467:4467 oryd/keto:latest-sqlite serve
```

6. Run the application:
```bash
go run cmd/server/main.go
```

The server will start on port 3000 by default. You can access:
- API endpoints: `http://localhost:3000/api/`
- Health check: `http://localhost:3000/health`

## 📊 API Documentation

### Authentication Endpoints

#### POST /auth/register
Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "role": "user"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "created_at": "2024-01-01T00:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### POST /auth/login
Authenticate user and receive JWT tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "expires_at": "2024-01-01T01:00:00Z"
    },
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "role": "user"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Authorization Examples

#### Check User Permissions
```go
// Check if user can read a specific document
allowed, err := permissionService.Check(ctx, &authzDomain.CheckRequest{
    Namespace: "documents",
    Object:    "doc-123",
    Relation:  "viewer",
    Subject: authzDomain.Subject{
        ID:   "user-456",
        Type: authzDomain.SubjectTypeUser,
    },
})
```

#### Grant Permissions
```go
// Make user an owner of a document
permission := &authzDomain.Permission{
    Namespace: "documents",
    Object:    "doc-123",
    Relation:  "owner",
    Subject: authzDomain.Subject{
        ID:   "user-456",
        Type: authzDomain.SubjectTypeUser,
    },
}
err := permissionService.CreateRelation(ctx, permission)
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | Database username | `postgres` |
| `DB_PASSWORD` | Database password | `password` |
| `DB_NAME` | Database name | `helms_deep` |
| `KETO_READ_URL` | Keto read API URL | `http://localhost:4466` |
| `KETO_WRITE_URL` | Keto write API URL | `http://localhost:4467` |
| `JWT_ACCESS_SECRET` | JWT access token secret | - |
| `JWT_REFRESH_SECRET` | JWT refresh token secret | - |
| `JWT_ACCESS_TTL` | Access token lifetime | `1h` |
| `JWT_REFRESH_TTL` | Refresh token lifetime | `720h` |

### ReBAC Namespaces

The system uses the following Keto namespaces:

- **users**: User-specific permissions
- **organizations**: Organization membership and roles
- **documents**: Document access control (example)

## 🚀 Deployment

### Docker

```bash
# Build the image
docker build -t helms-deep:latest .

# Run with docker-compose
docker-compose up -d
```

### Kubernetes

```bash
# Apply manifests
kubectl apply -f deployments/kubernetes/
```

## 🧪 Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

## 🚀 Why Fiber?

We chose **Fiber v2** over other Go web frameworks for several key reasons:

### Performance Benefits
- **10x faster** than standard net/http - built on fasthttp
- **Low memory footprint** - efficient memory allocation
- **Express.js-like API** - familiar for JavaScript/Node.js developers
- **Zero allocation router** - blazing fast route matching

### Developer Experience
- **Rich middleware ecosystem** - CORS, rate limiting, compression, etc.
- **Built-in features** - request validation, file serving, template engines
- **Easy testing** - simple testing utilities and mocks
- **Excellent documentation** - comprehensive guides and examples

### Production Ready
- **Robust error handling** - panic recovery and graceful shutdowns
- **Security headers** - helmet middleware for production security
- **Monitoring** - built-in metrics and health check endpoints
- **Scalability** - designed for high-concurrency applications

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [gofiber/fiber](https://github.com/gofiber/fiber) - Express.js-inspired web framework written in Go
- [ory/keto](https://github.com/ory/keto) - Google Zanzibar implementation for ReBAC
- [Vertical Slice Architecture](https://jimmybogard.com/vertical-slice-architecture/) - Feature-based code organization
- [Google Zanzibar Paper](https://research.google/pubs/pub48190/) - Global-scale authorization system
- [fasthttp](https://github.com/valyala/fasthttp) - Fast HTTP package for Go (Fiber's foundation)

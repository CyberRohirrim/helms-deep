package user

import (
	"context"
	"database/sql"
	"fmt"

	userDomain "github.com/CyberRohirrim/helms-deep/internal/users/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBExecutor interface for database operations
type DBExecutor interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row
	Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error)
}

// Repository implements the user repository using PostgreSQL
type Repository struct {
	db   DBExecutor
	pool *pgxpool.Pool // Keep reference to pool for transactions
}

// NewRepository creates a new user repository
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db:   db,
		pool: db,
	}
}

// Create creates a new user in the database
func (r *Repository) Create(ctx context.Context, user *userDomain.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, first_name, last_name, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.Exec(ctx, query,
		user.ID.String(),
		user.Email.String(),
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.Role.String(),
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *Repository) GetByID(ctx context.Context, id userDomain.UserID) (*userDomain.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	row := r.db.QueryRow(ctx, query, id.String())
	return r.scanUser(row)
}

// GetByEmail retrieves a user by email
func (r *Repository) GetByEmail(ctx context.Context, email userDomain.Email) (*userDomain.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	row := r.db.QueryRow(ctx, query, email.String())
	return r.scanUser(row)
}

// Update updates a user in the database
func (r *Repository) Update(ctx context.Context, user *userDomain.User) error {
	query := `
		UPDATE users
		SET email = $2, password_hash = $3, first_name = $4, last_name = $5, 
		    role = $6, updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.Exec(ctx, query,
		user.ID.String(),
		user.Email.String(),
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.Role.String(),
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Delete deletes a user by ID
func (r *Repository) Delete(ctx context.Context, id userDomain.UserID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ExistsByEmail checks if a user exists with the given email
func (r *Repository) ExistsByEmail(ctx context.Context, email userDomain.Email) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.QueryRow(ctx, query, email.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// GetUsersByRole retrieves users by role
func (r *Repository) GetUsersByRole(ctx context.Context, role userDomain.Role) ([]*userDomain.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
		FROM users
		WHERE role = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, role.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query users by role: %w", err)
	}
	defer rows.Close()

	var users []*userDomain.User
	for rows.Next() {
		user, err := r.scanUserFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// GetAllUsers retrieves all users with pagination
func (r *Repository) GetAllUsers(ctx context.Context, limit, offset int) ([]*userDomain.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*userDomain.User
	for rows.Next() {
		user, err := r.scanUserFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// CountUsers returns the total number of users
func (r *Repository) CountUsers(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM users`

	var count int64
	err := r.db.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// SearchUsers searches for users by name or email
func (r *Repository) SearchUsers(ctx context.Context, searchTerm string, limit, offset int) ([]*userDomain.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
		FROM users
		WHERE first_name ILIKE $1 OR last_name ILIKE $1 OR email ILIKE $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	searchPattern := "%" + searchTerm + "%"
	rows, err := r.db.Query(ctx, query, searchPattern, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer rows.Close()

	var users []*userDomain.User
	for rows.Next() {
		user, err := r.scanUserFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating search results: %w", err)
	}

	return users, nil
}

// scanUser scans a single user from a row
func (r *Repository) scanUser(row pgx.Row) (*userDomain.User, error) {
	var id, email, passwordHash, firstName, lastName, role string
	var createdAt, updatedAt sql.NullTime

	err := row.Scan(&id, &email, &passwordHash, &firstName, &lastName, &role, &createdAt, &updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	return r.buildUser(id, email, passwordHash, firstName, lastName, role, createdAt, updatedAt)
}

// scanUserFromRows scans a user from query rows
func (r *Repository) scanUserFromRows(rows pgx.Rows) (*userDomain.User, error) {
	var id, email, passwordHash, firstName, lastName, role string
	var createdAt, updatedAt sql.NullTime

	err := rows.Scan(&id, &email, &passwordHash, &firstName, &lastName, &role, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	return r.buildUser(id, email, passwordHash, firstName, lastName, role, createdAt, updatedAt)
}

// buildUser builds a user domain object from database fields
func (r *Repository) buildUser(id, email, passwordHash, firstName, lastName, role string, createdAt, updatedAt sql.NullTime) (*userDomain.User, error) {
	user, err := userDomain.NewUser(id, email, passwordHash, firstName, lastName, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create user domain object: %w", err)
	}

	if createdAt.Valid {
		user.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		user.UpdatedAt = updatedAt.Time
	}

	return user, nil
}

// Transaction executes a function within a database transaction
func (r *Repository) Transaction(ctx context.Context, fn func(*Repository) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		} else if err != nil {
			tx.Rollback(ctx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	// Create a new repository instance that uses the transaction
	txRepo := &Repository{
		db:   &txPool{tx: tx},
		pool: r.pool,
	}
	err = fn(txRepo)
	return err
}

// txPool wraps a transaction to implement the pool interface
type txPool struct {
	tx pgx.Tx
}

func (tp *txPool) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return tp.tx.QueryRow(ctx, query, args...)
}

func (tp *txPool) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return tp.tx.Query(ctx, query, args...)
}

func (tp *txPool) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return tp.tx.Exec(ctx, query, args...)
}

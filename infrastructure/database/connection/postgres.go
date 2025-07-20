package connection

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// PostgresDB represents a PostgreSQL database connection
type PostgresDB struct {
	Pool *pgxpool.Pool
	DB   *sql.DB // For migrations and raw SQL operations
}

// Config holds database configuration
type Config struct {
	Host        string
	Port        int
	Username    string
	Password    string
	Database    string
	SSLMode     string
	MaxConns    int32
	MinConns    int32
	MaxLifetime time.Duration
	MaxIdleTime time.Duration
	HealthCheck time.Duration
}

// NewPostgresConnection creates a new PostgreSQL connection
func NewPostgresConnection(config Config) (*PostgresDB, error) {
	// Build connection string for pgxpool
	poolDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)

	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(poolDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Set pool configuration
	poolConfig.MaxConns = config.MaxConns
	poolConfig.MinConns = config.MinConns
	poolConfig.MaxConnLifetime = config.MaxLifetime
	poolConfig.MaxConnIdleTime = config.MaxIdleTime
	poolConfig.HealthCheckPeriod = config.HealthCheck

	// Create connection pool
	pool, err := pgxpool.New(context.Background(), poolConfig.ConnString())
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Create standard sql.DB for migrations
	sqlDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)

	sqlDB, err := sql.Open("postgres", sqlDSN)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to create sql.DB: %w", err)
	}

	// Test sql.DB connection
	if err := sqlDB.PingContext(ctx); err != nil {
		pool.Close()
		sqlDB.Close()
		return nil, fmt.Errorf("failed to ping sql.DB: %w", err)
	}

	return &PostgresDB{
		Pool: pool,
		DB:   sqlDB,
	}, nil
}

// Close closes the database connections
func (db *PostgresDB) Close() error {
	var err error

	if db.Pool != nil {
		db.Pool.Close()
	}

	if db.DB != nil {
		if closeErr := db.DB.Close(); closeErr != nil {
			err = closeErr
		}
	}

	return err
}

// Health checks database health
func (db *PostgresDB) Health(ctx context.Context) error {
	if db.Pool == nil {
		return fmt.Errorf("database pool is nil")
	}

	return db.Pool.Ping(ctx)
}

// Stats returns connection pool statistics
func (db *PostgresDB) Stats() *pgxpool.Stat {
	if db.Pool == nil {
		return nil
	}
	return db.Pool.Stat()
}

// Transaction executes a function within a database transaction
func (db *PostgresDB) Transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.Pool.Begin(ctx)
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

	err = fn(tx)
	return err
}

// QueryRow executes a query that returns a single row
func (db *PostgresDB) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return db.Pool.QueryRow(ctx, query, args...)
}

// Query executes a query that returns multiple rows
func (db *PostgresDB) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return db.Pool.Query(ctx, query, args...)
}

// Exec executes a query that doesn't return rows
func (db *PostgresDB) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.Pool.Exec(ctx, query, args...)
}

// Acquire gets a connection from the pool
func (db *PostgresDB) Acquire(ctx context.Context) (*pgxpool.Conn, error) {
	return db.Pool.Acquire(ctx)
}

// DefaultConfig returns a default database configuration
func DefaultConfig() Config {
	return Config{
		Host:        "localhost",
		Port:        5432,
		Username:    "postgres",
		Password:    "password",
		Database:    "helms_deep",
		SSLMode:     "disable",
		MaxConns:    30,
		MinConns:    5,
		MaxLifetime: time.Hour,
		MaxIdleTime: time.Minute * 30,
		HealthCheck: time.Minute,
	}
}

// ConfigFromEnv creates configuration from environment variables
func ConfigFromEnv() Config {
	// This would typically read from os.Getenv()
	// For now, return default config
	return DefaultConfig()
}

// Migrate runs database migrations
func (db *PostgresDB) Migrate(migrationPath string) error {
	// This would integrate with a migration library like golang-migrate
	// For now, just a placeholder
	return nil
}

// IsConnectionError checks if an error is a connection error
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common connection errors
	switch err {
	case context.DeadlineExceeded, context.Canceled:
		return true
	}

	// Check error message for connection-related keywords
	errMsg := err.Error()
	connectionKeywords := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"no such host",
		"network is unreachable",
	}

	for _, keyword := range connectionKeywords {
		if contains(errMsg, keyword) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				anyIndexOf(s, substr) >= 0))
}

// anyIndexOf finds the index of a substring (simple implementation)
func anyIndexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// RetryableError wraps errors that should be retried
type RetryableError struct {
	Err error
}

func (e RetryableError) Error() string {
	return fmt.Sprintf("retryable error: %v", e.Err)
}

func (e RetryableError) Unwrap() error {
	return e.Err
}

// IsRetryableError checks if an error should be retried
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if IsConnectionError(err) {
		return true
	}

	// Add other retryable error conditions here
	return false
}

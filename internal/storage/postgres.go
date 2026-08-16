package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/logger"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

const (
	maxRetries     = 3
	retryInterval1 = 1 * time.Second
	retryInterval2 = 3 * time.Second
	retryInterval3 = 5 * time.Second
)

// PostgresStorage stores users and secrets in PostgreSQL.
type PostgresStorage struct {
	db         *sql.DB
	mu         sync.Mutex
	encryptKey []byte
}

// NewPostgresStorage opens PostgreSQL, applies migrations, and returns a storage instance.
// Payloads are encrypted at rest when encryptKey is non-empty (32-byte AES key).
func NewPostgresStorage(dsn string, encryptKey []byte) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	ps := &PostgresStorage{db: db, encryptKey: encryptKey}
	if err := ps.applyMigrations(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	logger.Log.Info("Connected to PostgreSQL and applied migrations")
	return ps, nil
}

func (ps *PostgresStorage) applyMigrations() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	migrationsPath := filepath.ToSlash(wd) + "/migrations"
	driver, err := postgres.WithInstance(ps.db, &postgres.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"postgres",
		driver,
	)
	if err != nil {
		logger.Log.Error("Failed to create migrate instance", zap.Error(err))
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		logger.Log.Error("Failed to apply migrations", zap.Error(err))
		return err
	}
	logger.Log.Info("Migrations applied successfully")
	return nil
}

func isRetriableDBError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcode.ConnectionException,
			pgerrcode.ConnectionDoesNotExist,
			pgerrcode.ConnectionFailure,
			pgerrcode.SQLClientUnableToEstablishSQLConnection,
			pgerrcode.SQLServerRejectedEstablishmentOfSQLConnection,
			pgerrcode.TransactionRollback,
			pgerrcode.SerializationFailure,
			pgerrcode.DeadlockDetected,
			pgerrcode.CannotConnectNow:
			return true
		}
		class := pgErr.SQLState()
		if strings.HasPrefix(class, "08") {
			return true
		}
	}
	return false
}

func (ps *PostgresStorage) executeWithRetry(ctx context.Context, fn func() error) error {
	intervals := []time.Duration{retryInterval1, retryInterval2, retryInterval3}
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetriableDBError(err) {
			return err
		}
		if i < maxRetries {
			logger.Log.Warn("Database operation failed, retrying",
				zap.Error(err),
				zap.Int("attempt", i+1),
				zap.Duration("interval", intervals[i]))
			time.Sleep(intervals[i])
		}
	}
	return lastErr
}

func (ps *PostgresStorage) CreateUser(ctx context.Context, email, passwordHash string) (*models.User, error) {
	var user models.User
	err := ps.executeWithRetry(ctx, func() error {
		return ps.db.QueryRowContext(ctx,
			`INSERT INTO users (email, password_hash) VALUES ($1, $2)
			 RETURNING id, email, password_hash, created_at`,
			email, passwordHash,
		).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (ps *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := ps.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (ps *PostgresStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := ps.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (ps *PostgresStorage) CreateSecret(ctx context.Context, secret *models.Secret) error {
	if secret.ID == "" {
		secret.ID = uuid.NewString()
	}
	now := time.Now()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	if secret.Version == 0 {
		secret.Version = 1
	}
	payload, err := encodePayload(secret.Payload, ps.encryptKey)
	if err != nil {
		return err
	}
	return ps.executeWithRetry(ctx, func() error {
		_, err := ps.db.ExecContext(ctx,
			`INSERT INTO secrets (id, user_id, type, name, metadata, payload, version, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			secret.ID, secret.UserID, secret.Type, secret.Name, secret.Metadata,
			payload, secret.Version, secret.CreatedAt, secret.UpdatedAt,
		)
		return err
	})
}

func (ps *PostgresStorage) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	secret.UpdatedAt = time.Now()
	secret.Version++
	payload, err := encodePayload(secret.Payload, ps.encryptKey)
	if err != nil {
		return err
	}
	return ps.executeWithRetry(ctx, func() error {
		res, err := ps.db.ExecContext(ctx,
			`UPDATE secrets SET type = $1, name = $2, metadata = $3, payload = $4,
			 version = $5, updated_at = $6, deleted_at = NULL
			 WHERE id = $7 AND user_id = $8 AND deleted_at IS NULL`,
			secret.Type, secret.Name, secret.Metadata, payload,
			secret.Version, secret.UpdatedAt, secret.ID, secret.UserID,
		)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (ps *PostgresStorage) DeleteSecret(ctx context.Context, userID, secretID string) error {
	now := time.Now()
	return ps.executeWithRetry(ctx, func() error {
		res, err := ps.db.ExecContext(ctx,
			`UPDATE secrets SET deleted_at = $1, updated_at = $1, version = version + 1
			 WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`,
			now, secretID, userID,
		)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (ps *PostgresStorage) GetSecret(ctx context.Context, userID, secretID string) (*models.Secret, error) {
	var secret models.Secret
	var deletedAt sql.NullTime
	err := ps.db.QueryRowContext(ctx,
		`SELECT id, user_id, type, name, metadata, payload, version, created_at, updated_at, deleted_at
		 FROM secrets WHERE id = $1 AND user_id = $2`,
		secretID, userID,
	).Scan(
		&secret.ID, &secret.UserID, &secret.Type, &secret.Name, &secret.Metadata,
		&secret.Payload, &secret.Version, &secret.CreatedAt, &secret.UpdatedAt, &deletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if deletedAt.Valid {
		secret.DeletedAt = &deletedAt.Time
	}
	secret.Payload, err = decodePayload(secret.Payload, ps.encryptKey)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func (ps *PostgresStorage) ListSecrets(ctx context.Context, userID string, secretType models.SecretType) ([]models.Secret, error) {
	query := `SELECT id, user_id, type, name, metadata, payload, version, created_at, updated_at, deleted_at
		FROM secrets WHERE user_id = $1 AND deleted_at IS NULL`
	args := []any{userID}
	if secretType != "" {
		query += ` AND type = $2`
		args = append(args, secretType)
	}
	query += ` ORDER BY updated_at DESC`

	rows, err := ps.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return ps.scanSecrets(rows)
}

func (ps *PostgresStorage) ListSecretsSince(ctx context.Context, userID string, since time.Time) ([]models.Secret, error) {
	rows, err := ps.db.QueryContext(ctx,
		`SELECT id, user_id, type, name, metadata, payload, version, created_at, updated_at, deleted_at
		 FROM secrets WHERE user_id = $1 AND updated_at > $2
		 ORDER BY updated_at ASC`,
		userID, since,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return ps.scanSecrets(rows)
}

func (ps *PostgresStorage) scanSecrets(rows *sql.Rows) ([]models.Secret, error) {
	var secrets []models.Secret
	for rows.Next() {
		var secret models.Secret
		var deletedAt sql.NullTime
		if err := rows.Scan(
			&secret.ID, &secret.UserID, &secret.Type, &secret.Name, &secret.Metadata,
			&secret.Payload, &secret.Version, &secret.CreatedAt, &secret.UpdatedAt, &deletedAt,
		); err != nil {
			return nil, err
		}
		if deletedAt.Valid {
			secret.DeletedAt = &deletedAt.Time
		}
		payload, decErr := decodePayload(secret.Payload, ps.encryptKey)
		if decErr != nil {
			return nil, decErr
		}
		secret.Payload = payload
		secrets = append(secrets, secret)
	}
	return secrets, rows.Err()
}

func (ps *PostgresStorage) Ping(ctx context.Context) error {
	return ps.db.PingContext(ctx)
}

func (ps *PostgresStorage) Close() error {
	return ps.db.Close()
}

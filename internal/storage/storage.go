// Package storage implements user and secret persistence in databases.
package storage

import (
	"context"
	"iter"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/models"
)

// Storage defines persistence operations for users and secrets.
type Storage interface {
	CreateUser(ctx context.Context, email, passwordHash string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)

	CreateSecret(ctx context.Context, secret *models.Secret) error
	UpdateSecret(ctx context.Context, secret *models.Secret) error
	DeleteSecret(ctx context.Context, userID, secretID string) error
	GetSecret(ctx context.Context, userID, secretID string) (*models.Secret, error)
	ListSecretsSeq(ctx context.Context, userID string, secretType models.SecretType) iter.Seq2[models.Secret, error]
	ListSecretsSince(ctx context.Context, userID string, since time.Time) ([]models.Secret, error)

	RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
	ListRevokedTokens(ctx context.Context) (map[string]time.Time, error)

	Ping(ctx context.Context) error
	Close() error
}

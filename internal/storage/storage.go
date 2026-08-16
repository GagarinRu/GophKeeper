// Package storage implements user and secret persistence in databases.
package storage

import (
	"context"
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
	ListSecrets(ctx context.Context, userID string, secretType models.SecretType) ([]models.Secret, error)
	ListSecretsSince(ctx context.Context, userID string, since time.Time) ([]models.Secret, error)

	Ping(ctx context.Context) error
	Close() error
}

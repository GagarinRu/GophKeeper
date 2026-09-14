package storage

import (
	"context"

	"github.com/GagarinRu/gophkeeper/internal/models"
)

// ListSecrets collects all secrets from ListSecretsSeq into a slice.
func ListSecrets(ctx context.Context, store Storage, userID string, secretType models.SecretType) ([]models.Secret, error) {
	var secrets []models.Secret
	for secret, err := range store.ListSecretsSeq(ctx, userID, secretType) {
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

package storage_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestMemStorage_UserAndSecretCRUD(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemStorage()

	user, err := store.CreateUser(ctx, "test@example.com", "hash")
	require.NoError(t, err)
	require.NotEmpty(t, user.ID)

	found, err := store.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	require.Equal(t, user.ID, found.ID)

	payload, err := json.Marshal(models.LoginPasswordPayload{
		Login:    "user",
		Password: "pass",
	})
	require.NoError(t, err)

	secret := &models.Secret{
		UserID:   user.ID,
		Type:     models.SecretTypeLoginPassword,
		Name:     "test",
		Metadata: "meta",
		Payload:  payload,
	}
	require.NoError(t, store.CreateSecret(ctx, secret))

	list, err := storage.ListSecrets(ctx, store, user.ID, "")
	require.NoError(t, err)
	require.Len(t, list, 1)

	got, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "test", got.Name)

	secret.Name = "updated"
	require.NoError(t, store.UpdateSecret(ctx, secret))

	updated, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Name)
	require.Equal(t, int64(2), updated.Version)

	require.NoError(t, store.DeleteSecret(ctx, user.ID, secret.ID))
	deleted, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)

	since, err := store.ListSecretsSince(ctx, user.ID, updated.UpdatedAt.Add(-1))
	require.NoError(t, err)
	require.NotEmpty(t, since)
}

func TestMemStorageEncryptedPayload(t *testing.T) {
	ctx := context.Background()
	key := crypto.KeyFromSecret("mem-key")
	store := storage.NewMemStorageWithKey(key)
	user, err := store.CreateUser(ctx, "enc@test.com", "hash")
	require.NoError(t, err)

	payload, err := json.Marshal(models.TextPayload{Content: "secret"})
	require.NoError(t, err)
	secret := &models.Secret{
		UserID:  user.ID,
		Type:    models.SecretTypeText,
		Name:    "enc",
		Payload: payload,
	}
	require.NoError(t, store.CreateSecret(ctx, secret))

	got, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.JSONEq(t, string(payload), string(got.Payload))
}

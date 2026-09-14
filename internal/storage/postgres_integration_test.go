package storage_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func chdirProjectRoot(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			require.NoError(t, os.Chdir(dir))
			return
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("project root not found")
		}
	}
}

func newPostgresStorage(t *testing.T) *storage.PostgresStorage {
	chdirProjectRoot(t)
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		dsn = "postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable"
	}
	key := crypto.KeyFromSecret("integration-test-key")
	store, err := storage.NewPostgresStorage(dsn, key)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	return store
}

func TestPostgresStorage_UserAndSecretCRUD(t *testing.T) {
	store := newPostgresStorage(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	email := "pg-" + uuid.NewString() + "@test.com"
	user, err := store.CreateUser(ctx, email, "hash")
	require.NoError(t, err)
	require.NotEmpty(t, user.ID)

	found, err := store.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, user.ID, found.ID)

	byID, err := store.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, email, byID.Email)

	missing, err := store.GetUserByEmail(ctx, "nobody@test.com")
	require.NoError(t, err)
	require.Nil(t, missing)

	payload, err := json.Marshal(models.LoginPasswordPayload{Login: "u", Password: "p"})
	require.NoError(t, err)
	secret := &models.Secret{
		UserID:   user.ID,
		Type:     models.SecretTypeLoginPassword,
		Name:     "cred",
		Metadata: "site",
		Payload:  payload,
	}
	require.NoError(t, store.CreateSecret(ctx, secret))
	require.NotEmpty(t, secret.ID)

	list, err := storage.ListSecrets(ctx, store, user.ID, "")
	require.NoError(t, err)
	require.Len(t, list, 1)

	typed, err := storage.ListSecrets(ctx, store, user.ID, models.SecretTypeLoginPassword)
	require.NoError(t, err)
	require.Len(t, typed, 1)

	got, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "cred", got.Name)

	secret.Name = "updated"
	require.NoError(t, store.UpdateSecret(ctx, secret))
	updated, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Name)
	require.Equal(t, int64(2), updated.Version)

	since := updated.UpdatedAt.Add(-time.Second)
	changes, err := store.ListSecretsSince(ctx, user.ID, since)
	require.NoError(t, err)
	require.NotEmpty(t, changes)

	require.NoError(t, store.DeleteSecret(ctx, user.ID, secret.ID))
	deleted, err := store.GetSecret(ctx, user.ID, secret.ID)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)

	require.NoError(t, store.Ping(ctx))
}

func TestPostgresStorage_AllSecretTypes(t *testing.T) {
	store := newPostgresStorage(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	user, err := store.CreateUser(ctx, "types-"+uuid.NewString()+"@test.com", "hash")
	require.NoError(t, err)

	textPayload, _ := json.Marshal(models.TextPayload{Content: "note"})
	binPayload, _ := json.Marshal(models.BinaryPayload{Filename: "f.bin", Data: []byte{1, 2}})
	cardPayload, _ := json.Marshal(models.CardPayload{Number: "4111", Holder: "A", Expiry: "12/30"})

	secrets := []*models.Secret{
		{UserID: user.ID, Type: models.SecretTypeText, Name: "t", Payload: textPayload},
		{UserID: user.ID, Type: models.SecretTypeBinary, Name: "b", Payload: binPayload},
		{UserID: user.ID, Type: models.SecretTypeCard, Name: "c", Payload: cardPayload},
	}
	for _, s := range secrets {
		require.NoError(t, store.CreateSecret(ctx, s))
	}

	list, err := storage.ListSecrets(ctx, store, user.ID, "")
	require.NoError(t, err)
	require.Len(t, list, 3)
}

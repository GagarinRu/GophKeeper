package client_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/client"
	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/stretchr/testify/require"
)

func TestAPIFullCRUD(t *testing.T) {
	var stored models.Secret
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/secrets":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]models.Secret{stored})
		case r.Method == http.MethodGet && r.URL.Path == "/api/secrets/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodPost && r.URL.Path == "/api/secrets":
			stored = models.Secret{ID: "1", Name: "n", Type: models.SecretTypeText}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodPut && r.URL.Path == "/api/secrets/1":
			stored.Name = "updated"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(stored)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/secrets/1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/sync":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]models.Secret{stored})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	api.SetToken("tok")

	payload, _ := json.Marshal(models.TextPayload{Content: "hi"})
	created, err := api.CreateSecret(models.SecretTypeText, "n", "", payload)
	require.NoError(t, err)
	require.Equal(t, "1", created.ID)

	list, err := api.ListSecrets("")
	require.NoError(t, err)
	require.Len(t, list, 1)

	got, err := api.GetSecret("1")
	require.NoError(t, err)
	require.Equal(t, "n", got.Name)

	updated, err := api.UpdateSecret("1", models.SecretTypeText, "updated", "", payload)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Name)

	synced, err := api.Sync(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, synced, 1)

	require.NoError(t, api.DeleteSecret("1"))
}

func TestAPIWithEncryption(t *testing.T) {
	dir := t.TempDir()
	publicPath, _ := crypto.WriteTestKeyPair(t, dir)
	pub, err := crypto.LoadPublicKey(publicPath)
	require.NoError(t, err)

	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.Secret{ID: "1"})
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	api.SetToken("tok")
	api.SetPublicKey(pub)
	payload, _ := json.Marshal(models.TextPayload{Content: "secret"})
	_, err = api.CreateSecret(models.SecretTypeText, "n", "", payload)
	require.NoError(t, err)
	require.NotContains(t, string(received), "secret")
}

func TestAPIListSecretsByType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/secrets?type=text", r.URL.Path+"?"+r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]models.Secret{})
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	api.SetToken("tok")
	_, err := api.ListSecrets(models.SecretTypeText)
	require.NoError(t, err)
}

func TestAPIRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad"}`))
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	api.SetToken("tok")
	_, err := api.GetSecret("x")
	require.Error(t, err)
}

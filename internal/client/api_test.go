package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/client"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/stretchr/testify/require"
)

func TestAPIPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	require.NoError(t, api.Ping())
}

func TestAPIRegisterLoginFlow(t *testing.T) {
	var token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/register":
			token = "test-token"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
		case "/api/login":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "login-token"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	got, err := api.Register("a@b.com", "pass")
	require.NoError(t, err)
	require.Equal(t, "test-token", got)

	got, err = api.Login("a@b.com", "pass")
	require.NoError(t, err)
	require.Equal(t, "login-token", got)
}

func TestAPICreateSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/secrets", r.URL.Path)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.Secret{ID: "1", Name: "n"})
	}))
	defer srv.Close()

	api := client.NewAPI(srv.URL)
	api.SetToken("tok")
	payload, _ := json.Marshal(models.TextPayload{Content: "hi"})
	secret, err := api.CreateSecret(models.SecretTypeText, "n", "", payload)
	require.NoError(t, err)
	require.Equal(t, "1", secret.ID)
}

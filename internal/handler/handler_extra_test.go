package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/handler"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestDecryptMiddleware(t *testing.T) {
	dir := t.TempDir()
	publicPath, privatePath := crypto.WriteTestKeyPair(t, dir)
	priv, err := crypto.LoadPrivateKey(privatePath)
	require.NoError(t, err)
	pub, err := crypto.LoadPublicKey(publicPath)
	require.NoError(t, err)

	store := storage.NewMemStorage()
	authSvc := auth.NewService(store, "test-secret")
	h := handler.NewHandler(store, authSvc, priv)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		var req map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, "value", req["key"])
	})

	body := []byte(`{"key":"value"}`)
	encrypted, err := crypto.Encrypt(body, pub)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/secrets", bytes.NewReader(encrypted))
	rec := httptest.NewRecorder()
	h.DecryptMiddleware(next).ServeHTTP(rec, req)
	require.True(t, called)
}

func TestCreateSecretInvalidPayload(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	token := registerAndGetToken(t, srv.URL)
	secretBody, _ := json.Marshal(map[string]any{
		"type":     models.SecretTypeLoginPassword,
		"name":     "n",
		"payload":  json.RawMessage(`{"login":""}`),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(secretBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerPingAndLoginFail(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ping")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	loginBody, _ := json.Marshal(map[string]string{"email": "x@y.com", "password": "wrong"})
	resp, err = http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerTwoClientsSyncSameUser(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	email := "two-client@test.com"
	regBody, _ := json.Marshal(map[string]string{"email": email, "password": "secret"})
	resp, err := http.Post(srv.URL+"/api/register", "application/json", bytes.NewReader(regBody))
	require.NoError(t, err)
	var token1 struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&token1))
	_ = resp.Body.Close()

	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": "secret"})
	resp, err = http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err)
	var token2 struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&token2))
	_ = resp.Body.Close()

	payload, _ := json.Marshal(models.TextPayload{Content: "shared"})
	secretBody, _ := json.Marshal(map[string]any{
		"type":    models.SecretTypeText,
		"name":    "note",
		"payload": json.RawMessage(payload),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(secretBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token1.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()

	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/sync", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token2.Token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var synced []models.Secret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&synced))
	require.Len(t, synced, 1)
	require.Equal(t, "note", synced[0].Name)
	_ = resp.Body.Close()
}

func TestHandlerRegisterDuplicateAndUpdate(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	token := registerAndGetToken(t, srv.URL)
	regBody, _ := json.Marshal(map[string]string{"email": "sync@test.com", "password": "secret"})
	resp, err := http.Post(srv.URL+"/api/register", "application/json", bytes.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	_ = resp.Body.Close()

	payload, _ := json.Marshal(models.CardPayload{Number: "4111", Holder: "A", Expiry: "12/30"})
	createBody, _ := json.Marshal(map[string]any{
		"type":    models.SecretTypeCard,
		"name":    "card",
		"payload": json.RawMessage(payload),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(createBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	var created models.Secret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()

	updatePayload, _ := json.Marshal(models.CardPayload{Number: "4222", Holder: "B", Expiry: "01/31"})
	updateBody, _ := json.Marshal(map[string]any{
		"name":    "card-updated",
		"payload": json.RawMessage(updatePayload),
	})
	req, err = http.NewRequest(http.MethodPut, srv.URL+"/api/secrets/"+created.ID, bytes.NewReader(updateBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated models.Secret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Equal(t, "card-updated", updated.Name)
	_ = resp.Body.Close()
}

func TestHandlerSyncInvalidSince(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()
	token := registerAndGetToken(t, srv.URL)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/sync?since=not-a-date", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerListSecretsInvalidType(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()
	token := registerAndGetToken(t, srv.URL)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/secrets?type=unknown", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerGetSecretNotFound(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()
	token := registerAndGetToken(t, srv.URL)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/secrets/missing", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()
}

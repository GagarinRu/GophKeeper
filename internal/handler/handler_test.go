package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/handler"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func newTestRouter() (*storage.MemStorage, *auth.Service, *httptest.Server) {
	store := storage.NewMemStorage()
	authSvc := auth.NewService(store, "test-secret")
	h := handler.NewHandler(store, authSvc, nil)
	r := chi.NewRouter()
	r.Post("/api/register", h.Register)
	r.Post("/api/login", h.Login)
	r.Get("/ping", h.Ping)
	r.Group(func(r chi.Router) {
		r.Use(authSvc.RequireAuth)
		r.Post("/api/secrets", h.CreateSecret)
		r.Get("/api/secrets", h.ListSecrets)
		r.Get("/api/sync", h.Sync)
		r.Get("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.GetSecret(w, r, chi.URLParam(r, "id"))
		})
		r.Put("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.UpdateSecret(w, r, chi.URLParam(r, "id"))
		})
		r.Delete("/api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) {
			h.DeleteSecret(w, r, chi.URLParam(r, "id"))
		})
	})
	return store, authSvc, httptest.NewServer(r)
}

func TestHandlerRegisterLoginAndCreateSecret(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	regBody, _ := json.Marshal(map[string]string{
		"email":    "a@b.com",
		"password": "secret",
	})
	resp, err := http.Post(srv.URL+"/api/register", "application/json", bytes.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var tokenResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))
	_ = resp.Body.Close()

	payload, _ := json.Marshal(models.LoginPasswordPayload{Login: "u", Password: "p"})
	secretBody, _ := json.Marshal(map[string]any{
		"type":     models.SecretTypeLoginPassword,
		"name":     "n",
		"metadata": "m",
		"payload":  json.RawMessage(payload),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(secretBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()

	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/secrets", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerUnauthorized(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/secrets")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestHandlerSyncAndDelete(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	token := registerAndGetToken(t, srv.URL)
	payload, _ := json.Marshal(models.TextPayload{Content: "hello"})
	secretBody, _ := json.Marshal(map[string]any{
		"type":     models.SecretTypeText,
		"name":     "note",
		"metadata": "",
		"payload":  json.RawMessage(payload),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(secretBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created models.Secret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()

	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/sync", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	req, err = http.NewRequest(http.MethodDelete, srv.URL+"/api/secrets/"+created.ID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	_ = resp.Body.Close()
}

func registerAndGetToken(t *testing.T, baseURL string) string {
	regBody, _ := json.Marshal(map[string]string{"email": "sync@test.com", "password": "secret"})
	resp, err := http.Post(baseURL+"/api/register", "application/json", bytes.NewReader(regBody))
	require.NoError(t, err)
	var tokenResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))
	_ = resp.Body.Close()
	return tokenResp.Token
}

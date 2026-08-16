package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/stretchr/testify/require"
)

func TestHandlerUpdateSecret(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	token := registerAndGetToken(t, srv.URL)
	payload, _ := json.Marshal(models.TextPayload{Content: "old"})
	secretBody, _ := json.Marshal(map[string]any{
		"type":    models.SecretTypeText,
		"name":    "note",
		"payload": json.RawMessage(payload),
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/secrets", bytes.NewReader(secretBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var created models.Secret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()

	updateBody, _ := json.Marshal(map[string]any{
		"name":     "updated",
		"metadata": "meta",
		"payload":  json.RawMessage(mustJSON(models.TextPayload{Content: "new"})),
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
	require.Equal(t, "updated", updated.Name)
	_ = resp.Body.Close()
}

func TestHandlerRegisterDuplicate(t *testing.T) {
	_, _, srv := newTestRouter()
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"email": "dup@test.com", "password": "secret"})
	resp, err := http.Post(srv.URL+"/api/register", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	_ = resp.Body.Close()

	resp, err = http.Post(srv.URL+"/api/register", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	_ = resp.Body.Close()
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

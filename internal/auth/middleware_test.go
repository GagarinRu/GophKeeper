package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestRequireAuth(t *testing.T) {
	store := storage.NewMemStorage()
	svc := auth.NewService(store, "secret")
	called := false
	handler := svc.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id, ok := auth.UserIDFromContext(r.Context())
		require.True(t, ok)
		require.NotEmpty(t, id)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, called)

	token, _, err := svc.Register(req.Context(), "auth@test.com", "password")
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, called)
}

package logger_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/logger"
	"github.com/stretchr/testify/require"
)

func TestRequestLoggerWithBody(t *testing.T) {
	require.NoError(t, logger.Initialize("info"))
	handler := logger.RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/secrets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
}

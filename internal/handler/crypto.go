package handler

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
)

// DecryptMiddleware decrypts RSA+AES request bodies for secret API endpoints.
func (h *Handler) DecryptMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.privateKey == nil {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if !strings.HasPrefix(path, "/api/secrets") {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
			return
		}
		if len(bodyBytes) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		decrypted, err := crypto.Decrypt(bodyBytes, h.privateKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid encrypted body"})
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(decrypted))
		next.ServeHTTP(w, r)
	})
}

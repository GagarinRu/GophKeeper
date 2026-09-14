package handler

import (
	"net/http"

	"github.com/GagarinRu/gophkeeper/internal/auth"
)

// NewMux returns an HTTP mux with all API routes registered.
func NewMux(h *Handler, authService *auth.Service) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /ping", h.Ping)
	mux.HandleFunc("POST /api/register", h.Register)
	mux.HandleFunc("POST /api/login", h.Login)

	withAuth := func(pattern string, handler http.HandlerFunc) {
		mux.Handle(pattern, authService.RequireAuth(http.HandlerFunc(handler)))
	}
	withAuth("POST /api/logout", h.Logout)
	withAuth("POST /api/secrets", h.CreateSecret)
	withAuth("GET /api/secrets", h.ListSecrets)
	withAuth("GET /api/sync", h.Sync)
	withAuth("GET /api/secrets/{id}", h.GetSecret)
	withAuth("PUT /api/secrets/{id}", h.UpdateSecret)
	withAuth("DELETE /api/secrets/{id}", h.DeleteSecret)

	return mux
}

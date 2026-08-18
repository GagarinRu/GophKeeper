// Package handler provides HTTP handlers for the GophKeeper server.
package handler

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/auth"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/GagarinRu/gophkeeper/internal/storage"
)

// Handler serves HTTP API endpoints.
type Handler struct {
	storage    storage.Storage
	auth       *auth.Service
	privateKey *rsa.PrivateKey
}

// NewHandler creates a handler with storage, auth service, and optional RSA private key for transport decryption.
func NewHandler(storage storage.Storage, authService *auth.Service, privateKey *rsa.PrivateKey) *Handler {
	return &Handler{storage: storage, auth: authService, privateKey: privateKey}
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type createSecretRequest struct {
	Type     models.SecretType `json:"type"`
	Name     string            `json:"name"`
	Metadata string            `json:"metadata"`
	Payload  json.RawMessage   `json:"payload"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Register handles POST /api/register and creates a new user account.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password required"})
		return
	}
	token, _, err := h.auth.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		if err.Error() == "user already exists" {
			writeJSON(w, http.StatusConflict, errorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "registration failed"})
		return
	}
	writeJSON(w, http.StatusCreated, tokenResponse{Token: token})
}

// Login handles POST /api/login and returns a JWT for valid credentials.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "email and password required"})
		return
	}
	token, _, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{Token: token})
}

// Logout handles POST /api/logout and revokes the current access token.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.BearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if err := h.auth.Logout(r.Context(), token); err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid token"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateSecret handles POST /api/secrets and stores a new secret for the authenticated user.
func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	var req createSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if !models.ValidSecretType(req.Type) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid secret type"})
		return
	}
	if err := validatePayload(req.Type, req.Payload); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	secret := &models.Secret{
		UserID:   userID,
		Type:     req.Type,
		Name:     req.Name,
		Metadata: req.Metadata,
		Payload:  req.Payload,
	}
	if err := h.storage.CreateSecret(r.Context(), secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to create secret"})
		return
	}
	writeJSON(w, http.StatusCreated, secret)
}

// ListSecrets handles GET /api/secrets and returns secrets filtered by optional type query param.
func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	secretType := models.SecretType(r.URL.Query().Get("type"))
	if secretType != "" && !models.ValidSecretType(secretType) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid secret type"})
		return
	}
	secrets, err := h.storage.ListSecrets(r.Context(), userID, secretType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to list secrets"})
		return
	}
	writeJSON(w, http.StatusOK, secrets)
}

// GetSecret handles GET /api/secrets/{id} and returns a single secret by ID.
func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	secret, err := h.storage.GetSecret(r.Context(), userID, secretID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to get secret"})
		return
	}
	if secret == nil || secret.DeletedAt != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "secret not found"})
		return
	}
	writeJSON(w, http.StatusOK, secret)
}

// UpdateSecret handles PUT /api/secrets/{id} and updates an existing secret.
func (h *Handler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	existing, err := h.storage.GetSecret(r.Context(), userID, secretID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to update secret"})
		return
	}
	if existing == nil || existing.DeletedAt != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "secret not found"})
		return
	}
	var req createSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.Type != "" && !models.ValidSecretType(req.Type) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid secret type"})
		return
	}
	secretType := existing.Type
	if req.Type != "" {
		secretType = req.Type
	}
	payload := existing.Payload
	if len(req.Payload) > 0 {
		payload = req.Payload
	}
	if err := validatePayload(secretType, payload); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	secret := &models.Secret{
		ID:       secretID,
		UserID:   userID,
		Type:     secretType,
		Name:     existing.Name,
		Metadata: existing.Metadata,
		Payload:  payload,
		Version:  existing.Version,
	}
	if req.Name != "" {
		secret.Name = req.Name
	}
	if req.Metadata != "" {
		secret.Metadata = req.Metadata
	}
	if err := h.storage.UpdateSecret(r.Context(), secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to update secret"})
		return
	}
	updated, err := h.storage.GetSecret(r.Context(), userID, secretID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to get secret"})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// DeleteSecret handles DELETE /api/secrets/{id} and soft-deletes a secret.
func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	if err := h.storage.DeleteSecret(r.Context(), userID, secretID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "secret not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Sync handles GET /api/sync and returns secrets changed since the optional since query param.
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
		return
	}
	sinceStr := r.URL.Query().Get("since")
	since := time.Time{}
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid since parameter"})
			return
		}
		since = parsed
	}
	secrets, err := h.storage.ListSecretsSince(r.Context(), userID, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "failed to sync secrets"})
		return
	}
	writeJSON(w, http.StatusOK, secrets)
}

// Ping handles GET /ping and checks database connectivity.
func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	if err := h.storage.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func validatePayload(secretType models.SecretType, payload json.RawMessage) error {
	if len(payload) == 0 {
		return errInvalidPayload
	}
	switch secretType {
	case models.SecretTypeLoginPassword:
		var p models.LoginPasswordPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return errInvalidPayload
		}
		if p.Login == "" || p.Password == "" {
			return errInvalidPayload
		}
	case models.SecretTypeText:
		var p models.TextPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return errInvalidPayload
		}
		if p.Content == "" {
			return errInvalidPayload
		}
	case models.SecretTypeBinary:
		var p models.BinaryPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return errInvalidPayload
		}
		if p.Filename == "" || len(p.Data) == 0 {
			return errInvalidPayload
		}
	case models.SecretTypeCard:
		var p models.CardPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return errInvalidPayload
		}
		if p.Number == "" || p.Holder == "" || p.Expiry == "" {
			return errInvalidPayload
		}
	default:
		return errInvalidPayload
	}
	return nil
}

var errInvalidPayload = errorString("invalid payload")

type errorString string

func (e errorString) Error() string { return string(e) }

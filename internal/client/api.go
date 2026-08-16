// Package client provides an HTTP API client for the server.
package client

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/GagarinRu/gophkeeper/internal/models"
)

// API is an HTTP client for the GophKeeper server.
type API struct {
	baseURL    string
	token      string
	publicKey  *rsa.PublicKey
	httpClient *http.Client
}

// NewAPI creates a client for the given server base URL.
func NewAPI(baseURL string) *API {
	return &API{
		baseURL: stringsTrimRightSlash(baseURL),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetToken sets the Bearer token for authenticated requests.
func (a *API) SetToken(token string) {
	a.token = token
}

// SetPublicKey sets the RSA public key for encrypting request bodies.
func (a *API) SetPublicKey(pub *rsa.PublicKey) {
	a.publicKey = pub
}

// Register creates a new user and returns a token.
func (a *API) Register(email, password string) (string, error) {
	var resp tokenResponse
	if err := a.postJSON("/api/register", credentialsRequest{Email: email, Password: password}, &resp); err != nil {
		return "", err
	}
	a.token = resp.Token
	return resp.Token, nil
}

// Login authenticates and returns a token.
func (a *API) Login(email, password string) (string, error) {
	var resp tokenResponse
	if err := a.postJSON("/api/login", credentialsRequest{Email: email, Password: password}, &resp); err != nil {
		return "", err
	}
	a.token = resp.Token
	return resp.Token, nil
}

// CreateSecret creates a secret on the server.
func (a *API) CreateSecret(secretType models.SecretType, name, metadata string, payload json.RawMessage) (*models.Secret, error) {
	req := createSecretRequest{
		Type:     secretType,
		Name:     name,
		Metadata: metadata,
		Payload:  payload,
	}
	var secret models.Secret
	if err := a.postJSON("/api/secrets", req, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// UpdateSecret updates a secret on the server.
func (a *API) UpdateSecret(id string, secretType models.SecretType, name, metadata string, payload json.RawMessage) (*models.Secret, error) {
	req := createSecretRequest{
		Type:     secretType,
		Name:     name,
		Metadata: metadata,
		Payload:  payload,
	}
	var secret models.Secret
	if err := a.doRequest(http.MethodPut, "/api/secrets/"+id, req, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// ListSecrets returns secrets for the authenticated user.
func (a *API) ListSecrets(secretType models.SecretType) ([]models.Secret, error) {
	path := "/api/secrets"
	if secretType != "" {
		path += "?type=" + string(secretType)
	}
	var secrets []models.Secret
	if err := a.getJSON(path, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

// GetSecret returns a single secret by ID.
func (a *API) GetSecret(id string) (*models.Secret, error) {
	var secret models.Secret
	if err := a.getJSON("/api/secrets/"+id, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// DeleteSecret removes a secret by ID.
func (a *API) DeleteSecret(id string) error {
	return a.doRequest(http.MethodDelete, "/api/secrets/"+id, nil, nil)
}

// Sync returns secrets changed since the given time.
func (a *API) Sync(since time.Time) ([]models.Secret, error) {
	path := "/api/sync"
	if !since.IsZero() {
		path += "?since=" + since.Format(time.RFC3339)
	}
	var secrets []models.Secret
	if err := a.getJSON(path, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

// Ping checks server and database availability.
func (a *API) Ping() error {
	return a.doRequest(http.MethodGet, "/ping", nil, nil)
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

func (a *API) postJSON(path string, body, out any) error {
	return a.doRequest(http.MethodPost, path, body, out)
}

func (a *API) getJSON(path string, out any) error {
	return a.doRequest(http.MethodGet, path, nil, out)
}

func (a *API) doRequest(method, path string, body, out any) error {
	var reader io.Reader
	var bodyBytes []byte
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyBytes = data
		if a.publicKey != nil && (method == http.MethodPost || method == http.MethodPut) {
			encrypted, err := crypto.Encrypt(bodyBytes, a.publicKey)
			if err != nil {
				return err
			}
			bodyBytes = encrypted
		}
		reader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequest(method, a.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed: status %d: %s", resp.StatusCode, string(data))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

func stringsTrimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// Package models defines user and secret data structures.
package models

import (
	"encoding/json"
	"time"
)

// SecretType identifies the kind of stored secret.
type SecretType string

const (
	// SecretTypeLoginPassword stores login and password credentials.
	SecretTypeLoginPassword SecretType = "login_password"
	// SecretTypeText stores arbitrary text content.
	SecretTypeText SecretType = "text"
	// SecretTypeBinary stores arbitrary binary data with a filename.
	SecretTypeBinary SecretType = "binary"
	// SecretTypeCard stores bank card fields.
	SecretTypeCard SecretType = "card"
)

// User represents a registered account.
type User struct {
	// ID is the unique user identifier assigned by the storage layer.
	ID string `json:"id"`
	// Email is the user's login email address.
	Email string `json:"email"`
	// PasswordHash holds the bcrypt hash; never exposed in API responses.
	PasswordHash string `json:"-"`
	// CreatedAt is the account creation timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// Secret is a private record owned by a user.
type Secret struct {
	// ID is the unique secret identifier.
	ID string `json:"id"`
	// UserID is the owner of this secret.
	UserID string `json:"user_id"`
	// Type determines how Payload is interpreted.
	Type SecretType `json:"type"`
	// Name is a human-readable label for the secret.
	Name string `json:"name"`
	// Metadata holds arbitrary text (site, person, bank notes, OTP hints, etc.).
	Metadata string `json:"metadata"`
	// Payload is the type-specific JSON body (login/password, text, binary, card).
	Payload json.RawMessage `json:"payload"`
	// Version increments on each update for sync conflict detection.
	Version int64 `json:"version"`
	// CreatedAt is when the secret was first stored.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the last modification timestamp.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is set when the secret is soft-deleted.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// LoginPasswordPayload holds credentials for a login/password secret.
type LoginPasswordPayload struct {
	// Login is the account username or email on the target site.
	Login string `json:"login"`
	// Password is the account password.
	Password string `json:"password"`
	// URL is an optional link to the service.
	URL string `json:"url,omitempty"`
}

// TextPayload holds arbitrary text data.
type TextPayload struct {
	// Content is the stored text.
	Content string `json:"content"`
}

// BinaryPayload holds arbitrary binary data.
type BinaryPayload struct {
	// Filename is the original file name for the binary blob.
	Filename string `json:"filename"`
	// Data is the raw binary content.
	Data []byte `json:"data"`
}

// CardPayload holds bank card fields.
type CardPayload struct {
	// Number is the card number.
	Number string `json:"number"`
	// Holder is the cardholder name.
	Holder string `json:"holder"`
	// Expiry is the expiration date (e.g. MM/YY).
	Expiry string `json:"expiry"`
	// CVV is the optional card verification value.
	CVV string `json:"cvv,omitempty"`
}

// ValidSecretType reports whether t is a supported secret type.
func ValidSecretType(t SecretType) bool {
	switch t {
	case SecretTypeLoginPassword, SecretTypeText, SecretTypeBinary, SecretTypeCard:
		return true
	default:
		return false
	}
}

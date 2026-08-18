package storage

import (
	"context"
	"database/sql"
	"errors"
	"iter"
	"sync"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/google/uuid"
)

// MemStorage is an in-memory Storage implementation for tests.
type MemStorage struct {
	mu             sync.RWMutex
	users          map[string]*models.User
	secrets        map[string]*models.Secret
	revokedTokens  map[string]time.Time
	encryptKey     []byte
}

// NewMemStorage returns an empty in-memory storage.
func NewMemStorage() *MemStorage {
	return NewMemStorageWithKey(nil)
}

// NewMemStorageWithKey returns in-memory storage with optional payload encryption.
func NewMemStorageWithKey(encryptKey []byte) *MemStorage {
	return &MemStorage{
		users:         make(map[string]*models.User),
		secrets:       make(map[string]*models.Secret),
		revokedTokens: make(map[string]time.Time),
		encryptKey:    encryptKey,
	}
}

func (m *MemStorage) CreateUser(ctx context.Context, email, passwordHash string) (*models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == email {
			return nil, errors.New("user already exists")
		}
	}
	user := &models.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
	}
	m.users[user.ID] = user
	return user, nil
}

func (m *MemStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (m *MemStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *MemStorage) CreateSecret(ctx context.Context, secret *models.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if secret.ID == "" {
		secret.ID = uuid.NewString()
	}
	now := time.Now()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	if secret.Version == 0 {
		secret.Version = 1
	}
	payload, err := encodePayload(secret.Payload, m.encryptKey)
	if err != nil {
		return err
	}
	cp := *secret
	cp.Payload = payload
	m.secrets[secret.ID] = &cp
	secret.Payload = payload
	return nil
}

func (m *MemStorage) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.secrets[secret.ID]
	if !ok || existing.UserID != secret.UserID || existing.DeletedAt != nil {
		return sql.ErrNoRows
	}
	secret.UpdatedAt = time.Now()
	secret.Version = existing.Version + 1
	secret.CreatedAt = existing.CreatedAt
	secret.DeletedAt = nil
	payload, err := encodePayload(secret.Payload, m.encryptKey)
	if err != nil {
		return err
	}
	secret.Payload = payload
	cp := *secret
	m.secrets[secret.ID] = &cp
	return nil
}

func (m *MemStorage) DeleteSecret(ctx context.Context, userID, secretID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.secrets[secretID]
	if !ok || existing.UserID != userID || existing.DeletedAt != nil {
		return sql.ErrNoRows
	}
	now := time.Now()
	existing.DeletedAt = &now
	existing.UpdatedAt = now
	existing.Version++
	return nil
}

func (m *MemStorage) GetSecret(ctx context.Context, userID, secretID string) (*models.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.secrets[secretID]
	if !ok || s.UserID != userID {
		return nil, nil
	}
	cp := *s
	payload, err := decodePayload(cp.Payload, m.encryptKey)
	if err != nil {
		return nil, err
	}
	cp.Payload = payload
	return &cp, nil
}

func (m *MemStorage) ListSecrets(ctx context.Context, userID string, secretType models.SecretType) ([]models.Secret, error) {
	var out []models.Secret
	for secret, err := range m.ListSecretsSeq(ctx, userID, secretType) {
		if err != nil {
			return nil, err
		}
		out = append(out, secret)
	}
	return out, nil
}

func (m *MemStorage) ListSecretsSeq(ctx context.Context, userID string, secretType models.SecretType) iter.Seq2[models.Secret, error] {
	return func(yield func(models.Secret, error) bool) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		for _, s := range m.secrets {
			if s.UserID != userID || s.DeletedAt != nil {
				continue
			}
			if secretType != "" && s.Type != secretType {
				continue
			}
			cp := *s
			payload, err := decodePayload(cp.Payload, m.encryptKey)
			if err != nil {
				yield(models.Secret{}, err)
				return
			}
			cp.Payload = payload
			if !yield(cp, nil) {
				return
			}
		}
	}
}

func (m *MemStorage) ListSecretsSince(ctx context.Context, userID string, since time.Time) ([]models.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []models.Secret
	for _, s := range m.secrets {
		if s.UserID != userID || !s.UpdatedAt.After(since) {
			continue
		}
		cp := *s
		payload, err := decodePayload(cp.Payload, m.encryptKey)
		if err != nil {
			return nil, err
		}
		cp.Payload = payload
		out = append(out, cp)
	}
	return out, nil
}

func (m *MemStorage) Ping(ctx context.Context) error {
	return nil
}

func (m *MemStorage) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedTokens[jti] = expiresAt
	return nil
}

func (m *MemStorage) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	expiresAt, ok := m.revokedTokens[jti]
	if !ok {
		return false, nil
	}
	if time.Now().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

func (m *MemStorage) Close() error {
	return nil
}

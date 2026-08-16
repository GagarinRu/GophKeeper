package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/models"
)

// Cache stores synced secrets locally.
type Cache struct {
	LastSync time.Time   `json:"last_sync"`
	Secrets  []models.Secret `json:"secrets"`
}

// LoadCache reads the cache file from disk.
func LoadCache(path string) (*Cache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Cache{}, nil
		}
		return nil, err
	}
	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

// SaveCache writes the cache file to disk.
func SaveCache(path string, cache *Cache) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// MergeSecrets updates the cache with synced secrets (last-write-wins by updated_at).
func MergeSecrets(cache *Cache, incoming []models.Secret) {
	byID := make(map[string]models.Secret, len(cache.Secrets))
	for _, s := range cache.Secrets {
		byID[s.ID] = s
	}
	for _, s := range incoming {
		if existing, ok := byID[s.ID]; ok && existing.UpdatedAt.After(s.UpdatedAt) {
			continue
		}
		byID[s.ID] = s
	}
	cache.Secrets = make([]models.Secret, 0, len(byID))
	for _, s := range byID {
		if s.DeletedAt != nil {
			continue
		}
		cache.Secrets = append(cache.Secrets, s)
	}
	if len(incoming) > 0 {
		last := incoming[len(incoming)-1].UpdatedAt
		if last.After(cache.LastSync) {
			cache.LastSync = last
		}
	}
}

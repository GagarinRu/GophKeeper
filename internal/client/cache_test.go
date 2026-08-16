package client_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/client"
	"github.com/GagarinRu/gophkeeper/internal/models"
	"github.com/stretchr/testify/require"
)

func TestMergeSecrets(t *testing.T) {
	cache := &client.Cache{
		Secrets: []models.Secret{
			{ID: "1", Name: "old", UpdatedAt: time.Now().Add(-2 * time.Hour)},
		},
	}
	newer := time.Now()
	client.MergeSecrets(cache, []models.Secret{
		{ID: "1", Name: "new", UpdatedAt: newer},
		{ID: "2", Name: "added", UpdatedAt: newer},
	})
	require.Len(t, cache.Secrets, 2)
	names := map[string]bool{}
	for _, s := range cache.Secrets {
		names[s.Name] = true
	}
	require.True(t, names["new"])
	require.True(t, names["added"])
}

func TestLoadSaveCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	cache := &client.Cache{
		LastSync: time.Now(),
		Secrets:  []models.Secret{{ID: "1", Name: "test"}},
	}
	require.NoError(t, client.SaveCache(path, cache))
	loaded, err := client.LoadCache(path)
	require.NoError(t, err)
	require.Len(t, loaded.Secrets, 1)
}

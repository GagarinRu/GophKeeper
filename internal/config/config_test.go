package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GagarinRu/gophkeeper/internal/config"
	"github.com/stretchr/testify/require"
)

func TestApplyServerJSON(t *testing.T) {
	opts := config.ServerOptions{
		Address:  ":8080",
		LogLevel: "info",
	}
	file := config.ServerJSON{
		Address:     "localhost:9090",
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "secret",
		LogLevel:    "debug",
		CryptoKey:   "/keys/private.pem",
	}
	merged, err := config.ApplyServerJSON(opts, file)
	require.NoError(t, err)
	require.Equal(t, "localhost:9090", merged.Address)
	require.Equal(t, "postgres://localhost/db", merged.DatabaseDSN)
	require.Equal(t, "secret", merged.JWTSecret)
	require.Equal(t, "debug", merged.LogLevel)
	require.Equal(t, "/keys/private.pem", merged.CryptoKeyPath)
}

func TestApplyServerJSONTokenTTL(t *testing.T) {
	opts := config.ServerOptions{TokenTTL: config.DefaultServerOptions().TokenTTL}
	file := config.ServerJSON{TokenTTL: "2h"}
	merged, err := config.ApplyServerJSON(opts, file)
	require.NoError(t, err)
	require.Equal(t, 2*time.Hour, merged.TokenTTL)
}

func TestApplyServerEnv(t *testing.T) {
	opts := config.ServerOptions{}
	t.Setenv("ADDRESS", "localhost:3000")
	t.Setenv("JWT_SECRET", "from-env")
	t.Setenv("DATABASE_DSN", "postgres://env/db")
	merged := config.ApplyServerEnv(opts)
	require.Equal(t, "localhost:3000", merged.Address)
	require.Equal(t, "from-env", merged.JWTSecret)
	require.Equal(t, "postgres://env/db", merged.DatabaseDSN)
}

func TestReadServerJSONFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"address": ":9000",
		"jwt_secret": "file-secret",
		"log_level": "warn"
	}`), 0o600))

	file, err := config.ReadServerJSON(path)
	require.NoError(t, err)
	require.Equal(t, ":9000", file.Address)
	require.Equal(t, "file-secret", file.JWTSecret)
	require.Equal(t, "warn", file.LogLevel)
}

func TestApplyClientJSON(t *testing.T) {
	opts := config.ClientOptions{
		ServerURL: "http://localhost:8080",
		LogLevel:  "info",
	}
	file := config.ClientJSON{
		ServerURL: "http://remote:8080",
		TokenFile: "/tmp/token",
		LogLevel:  "debug",
		CryptoKey: "/keys/public.pem",
	}
	merged, err := config.ApplyClientJSON(opts, file)
	require.NoError(t, err)
	require.Equal(t, "http://remote:8080", merged.ServerURL)
	require.Equal(t, "/tmp/token", merged.TokenFile)
	require.Equal(t, "debug", merged.LogLevel)
	require.Equal(t, "/keys/public.pem", merged.CryptoKeyPath)
}

func TestApplyClientEnv(t *testing.T) {
	opts := config.ClientOptions{ServerURL: "http://default:8080"}
	t.Setenv("SERVER_URL", "http://env:8080")
	t.Setenv("TOKEN_FILE", "/env/token")
	merged := config.ApplyClientEnv(opts)
	require.Equal(t, "http://env:8080", merged.ServerURL)
	require.Equal(t, "/env/token", merged.TokenFile)
}

func TestDefaultClientOptions(t *testing.T) {
	t.Setenv("SERVER_URL", "http://env:9000")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("TOKEN_FILE", "/env/token")
	t.Setenv("CACHE_FILE", "/env/cache.json")
	opts := config.DefaultClientOptions()
	require.Equal(t, "http://env:9000", opts.ServerURL)
	require.Equal(t, "debug", opts.LogLevel)
	require.Equal(t, "/env/token", opts.TokenFile)
	require.Equal(t, "/env/cache.json", opts.CacheFile)
}

func TestDefaultServerOptions(t *testing.T) {
	t.Setenv("ADDRESS", ":9000")
	t.Setenv("JWT_SECRET", "env-secret")
	opts := config.DefaultServerOptions()
	require.Equal(t, ":9000", opts.Address)
	require.Equal(t, "env-secret", opts.JWTSecret)
}

func TestConfigPathFromEnv(t *testing.T) {
	t.Setenv("CONFIG", "/etc/gophkeeper.json")
	require.Equal(t, "/etc/gophkeeper.json", config.ConfigPath())
}

package config

import (
	"os"
	"strings"
)

const (
	defaultServerAddress = ":8080"
	defaultServerLogLevel = "info"
	defaultJWTSecret      = "dev-secret-change-me"
)
// ServerJSON is the JSON config format for the GophKeeper server.
type ServerJSON struct {
	Address           string `json:"address"`
	DatabaseDSN       string `json:"database_dsn"`
	JWTSecret         string `json:"jwt_secret"`
	DataEncryptionKey string `json:"data_encryption_key"`
	LogLevel          string `json:"log_level"`
	CryptoKey         string `json:"crypto_key"`
}

// ServerOptions holds resolved server configuration.
type ServerOptions struct {
	Address           string
	DatabaseDSN       string
	JWTSecret         string
	DataEncryptionKey string
	LogLevel          string
	CryptoKeyPath     string
}

// ReadServerJSON loads server configuration from a JSON file.
func ReadServerJSON(path string) (ServerJSON, error) {
	var file ServerJSON
	if err := loadJSON(path, &file); err != nil {
		return file, err
	}
	return file, nil
}

// ApplyServerJSON merges JSON values into options.
func ApplyServerJSON(opts ServerOptions, file ServerJSON) (ServerOptions, error) {
	if file.Address != "" {
		opts.Address = file.Address
	}
	if file.DatabaseDSN != "" {
		opts.DatabaseDSN = file.DatabaseDSN
	}
	if file.JWTSecret != "" {
		opts.JWTSecret = file.JWTSecret
	}
	if file.DataEncryptionKey != "" {
		opts.DataEncryptionKey = file.DataEncryptionKey
	}
	if file.LogLevel != "" {
		opts.LogLevel = file.LogLevel
	}
	if file.CryptoKey != "" {
		opts.CryptoKeyPath = file.CryptoKey
	}
	return opts, nil
}

// ApplyServerEnv applies environment variables to server options.
func ApplyServerEnv(opts ServerOptions) ServerOptions {
	opts.Address = envString("ADDRESS", opts.Address)
	opts.DatabaseDSN = envString("DATABASE_DSN", opts.DatabaseDSN)
	opts.JWTSecret = envString("JWT_SECRET", opts.JWTSecret)
	opts.DataEncryptionKey = envString("DATA_ENCRYPTION_KEY", opts.DataEncryptionKey)
	opts.LogLevel = envString("LOG_LEVEL", opts.LogLevel)
	opts.CryptoKeyPath = envString("CRYPTO_KEY", opts.CryptoKeyPath)
	return opts
}

// DefaultServerOptions returns server options from environment with code fallbacks.
// Env: ADDRESS, DATABASE_DSN, JWT_SECRET, LOG_LEVEL, CRYPTO_KEY.
func DefaultServerOptions() ServerOptions {
	opts := ServerOptions{
		Address:   defaultServerAddress,
		LogLevel:  defaultServerLogLevel,
		JWTSecret: defaultJWTSecret,
	}
	return ApplyServerEnv(opts)
}

func envString(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return strings.Trim(val, `"'`)
	}
	return fallback
}

func envStringFirst(keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	fallback := keys[len(keys)-1]
	for _, key := range keys[:len(keys)-1] {
		if val, ok := os.LookupEnv(key); ok {
			return strings.Trim(val, `"'`)
		}
	}
	return fallback
}

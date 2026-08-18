package config

import (
	"os"
	"strings"
	"time"
)

const (
	defaultServerAddress  = ":8080"
	defaultServerLogLevel = "info"
	defaultJWTSecret      = "dev-secret-change-me"
	defaultTokenTTL       = 24 * time.Hour
)

// ServerJSON is the JSON config format for the GophKeeper server.
type ServerJSON struct {
	Address           string `json:"address"`
	DatabaseDSN       string `json:"database_dsn"`
	JWTSecret         string `json:"jwt_secret"`
	DataEncryptionKey string `json:"data_encryption_key"`
	LogLevel          string `json:"log_level"`
	CryptoKey         string `json:"crypto_key"`
	TokenTTL          string `json:"token_ttl"`
}

// ServerOptions holds resolved server configuration.
type ServerOptions struct {
	Address           string
	DatabaseDSN       string
	JWTSecret         string
	DataEncryptionKey string
	LogLevel          string
	CryptoKeyPath     string
	TokenTTL          time.Duration
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
	opts = applyOptions(opts,
		nonEmptyStringOption(file.Address, func(o *ServerOptions, v string) { o.Address = v }),
		nonEmptyStringOption(file.DatabaseDSN, func(o *ServerOptions, v string) { o.DatabaseDSN = v }),
		nonEmptyStringOption(file.JWTSecret, func(o *ServerOptions, v string) { o.JWTSecret = v }),
		nonEmptyStringOption(file.DataEncryptionKey, func(o *ServerOptions, v string) { o.DataEncryptionKey = v }),
		nonEmptyStringOption(file.LogLevel, func(o *ServerOptions, v string) { o.LogLevel = v }),
		nonEmptyStringOption(file.CryptoKey, func(o *ServerOptions, v string) { o.CryptoKeyPath = v }),
	)
	if file.TokenTTL != "" {
		secs, err := parseDurationSeconds(file.TokenTTL)
		if err != nil {
			return opts, err
		}
		opts.TokenTTL = time.Duration(secs) * time.Second
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
	if raw := envString("TOKEN_TTL", ""); raw != "" {
		if secs, err := parseDurationSeconds(raw); err == nil {
			opts.TokenTTL = time.Duration(secs) * time.Second
		}
	}
	return opts
}

// DefaultServerOptions returns server options from environment with code fallbacks.
// Env: ADDRESS, DATABASE_DSN, JWT_SECRET, DATA_ENCRYPTION_KEY, LOG_LEVEL, CRYPTO_KEY, TOKEN_TTL.
func DefaultServerOptions() ServerOptions {
	opts := ServerOptions{
		Address:   defaultServerAddress,
		LogLevel:  defaultServerLogLevel,
		JWTSecret: defaultJWTSecret,
		TokenTTL:  defaultTokenTTL,
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

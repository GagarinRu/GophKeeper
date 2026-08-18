package config

import (
	"os"
	"path/filepath"
)

const (
	defaultClientServerURL = "http://localhost:8080"
	defaultClientLogLevel  = "info"
)

// ClientJSON is the JSON config format for the GophKeeper CLI client.
type ClientJSON struct {
	ServerURL string `json:"server_url"`
	TokenFile string `json:"token_file"`
	CacheFile string `json:"cache_file"`
	LogLevel  string `json:"log_level"`
	CryptoKey string `json:"crypto_key"`
}

// ClientOptions holds resolved client configuration.
type ClientOptions struct {
	ServerURL     string
	TokenFile     string
	CacheFile     string
	LogLevel      string
	CryptoKeyPath string
}

// ReadClientJSON loads client configuration from a JSON file.
func ReadClientJSON(path string) (ClientJSON, error) {
	var file ClientJSON
	if err := loadJSON(path, &file); err != nil {
		return file, err
	}
	return file, nil
}

// ApplyClientJSON merges JSON values into options.
func ApplyClientJSON(opts ClientOptions, file ClientJSON) (ClientOptions, error) {
	return applyOptions(opts,
		nonEmptyStringOption(file.ServerURL, func(o *ClientOptions, v string) { o.ServerURL = v }),
		nonEmptyStringOption(file.TokenFile, func(o *ClientOptions, v string) { o.TokenFile = v }),
		nonEmptyStringOption(file.CacheFile, func(o *ClientOptions, v string) { o.CacheFile = v }),
		nonEmptyStringOption(file.LogLevel, func(o *ClientOptions, v string) { o.LogLevel = v }),
		nonEmptyStringOption(file.CryptoKey, func(o *ClientOptions, v string) { o.CryptoKeyPath = v }),
	), nil
}

// ApplyClientEnv applies environment variables to client options.
func ApplyClientEnv(opts ClientOptions) ClientOptions {
	opts.ServerURL = envStringFirst("SERVER_URL", "ADDRESS", opts.ServerURL)
	opts.TokenFile = envString("TOKEN_FILE", opts.TokenFile)
	opts.CacheFile = envString("CACHE_FILE", opts.CacheFile)
	opts.LogLevel = envString("LOG_LEVEL", opts.LogLevel)
	opts.CryptoKeyPath = envString("CRYPTO_KEY", opts.CryptoKeyPath)
	return opts
}

// DefaultClientOptions returns client options from environment with code fallbacks.
// Env: SERVER_URL or ADDRESS, TOKEN_FILE, CACHE_FILE, LOG_LEVEL, CRYPTO_KEY.
func DefaultClientOptions() ClientOptions {
	opts := ClientOptions{
		ServerURL: defaultClientServerURL,
		LogLevel:  defaultClientLogLevel,
		TokenFile: DefaultTokenPath(),
		CacheFile: DefaultCachePath(),
	}
	return ApplyClientEnv(opts)
}

// DefaultTokenPath returns the default path for the auth token file.
func DefaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".gophkeeper_token"
	}
	return filepath.Join(home, ".gophkeeper", "token")
}

// DefaultCachePath returns the default path for the local sync cache file.
func DefaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".gophkeeper_cache.json"
	}
	return filepath.Join(home, ".gophkeeper", "cache.json")
}

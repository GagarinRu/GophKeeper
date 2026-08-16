package main

import (
	"flag"
	"os"

	"github.com/GagarinRu/gophkeeper/internal/config"
)

func main() {
	opts := config.DefaultClientOptions()

	if configPath := config.ConfigPath(); configPath != "" {
		file, err := config.ReadClientJSON(configPath)
		if err != nil {
			panic("failed to load config: " + err.Error())
		}
		opts, err = config.ApplyClientJSON(opts, file)
		if err != nil {
			panic("failed to apply config: " + err.Error())
		}
	}

	var (
		serverURL string
		logLevel  string
		tokenFile string
		cacheFile string
		cryptoKey string
	)
	flag.StringVar(&serverURL, "a", opts.ServerURL, "Server address")
	flag.StringVar(&logLevel, "l", opts.LogLevel, "Log level")
	flag.StringVar(&tokenFile, "token-file", opts.TokenFile, "Path to token file")
	flag.StringVar(&cacheFile, "cache-file", opts.CacheFile, "Path to local cache file")
	flag.StringVar(&cryptoKey, "crypto-key", opts.CryptoKeyPath, "Path to public key for encryption")
	flag.StringVar(new(string), "c", "", "Path to JSON config file")
	flag.StringVar(new(string), "config", "", "Path to JSON config file")
	flag.Parse()

	visited := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	if visited["a"] {
		opts.ServerURL = serverURL
	}
	if visited["l"] {
		opts.LogLevel = logLevel
	}
	if visited["token-file"] {
		opts.TokenFile = tokenFile
	}
	if visited["cache-file"] {
		opts.CacheFile = cacheFile
	}
	if visited["crypto-key"] {
		opts.CryptoKeyPath = cryptoKey
	}

	opts = config.ApplyClientEnv(opts)

	cfg := cliConfig{
		ServerURL:     opts.ServerURL,
		TokenFile:     opts.TokenFile,
		CacheFile:     opts.CacheFile,
		LogLevel:      opts.LogLevel,
		CryptoKeyPath: opts.CryptoKeyPath,
	}

	os.Exit(runCLI(cfg, flag.Args()))
}

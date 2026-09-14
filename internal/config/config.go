// Package config provides JSON configuration loading for server and client.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ConfigPath returns the config file path from CONFIG env or -c/-config flags.
func ConfigPath() string {
	if path, ok := os.LookupEnv("CONFIG"); ok && path != "" {
		return strings.Trim(path, `"'`)
	}
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-c", arg == "-config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "-c="):
			return strings.TrimPrefix(arg, "-c=")
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		}
	}
	return ""
}

func loadJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}
	return nil
}

func parseDurationSeconds(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if d, err := time.ParseDuration(raw); err == nil {
		secs := int(d.Seconds())
		if secs <= 0 && d > 0 {
			return 1, nil
		}
		return secs, nil
	}
	return 0, fmt.Errorf("invalid duration %q", raw)
}

// Option is a functional option for setting configuration values.
type Option[T any] func(*T) error

func applyOptions[T any](base T, opts ...Option[T]) (T, error) {
	for _, opt := range opts {
		if err := opt(&base); err != nil {
			return base, err
		}
	}
	return base, nil
}

func nonEmptyStringOption[T any](value string, set func(*T, string)) Option[T] {
	return func(t *T) error {
		if value != "" {
			set(t, value)
		}
		return nil
	}
}

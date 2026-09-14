package auth

import (
	"sync"
	"time"
)

type revokedTokenCache struct {
	mu     sync.RWMutex
	tokens map[string]time.Time
}

func newRevokedTokenCache() *revokedTokenCache {
	return &revokedTokenCache{tokens: make(map[string]time.Time)}
}

func (c *revokedTokenCache) add(jti string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[jti] = expiresAt
	c.cleanup()
}

func (c *revokedTokenCache) isRevoked(jti string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	expiresAt, ok := c.tokens[jti]
	if !ok {
		return false
	}
	return time.Now().Before(expiresAt)
}

func (c *revokedTokenCache) replace(tokens map[string]time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = tokens
	c.cleanup()
}

func (c *revokedTokenCache) cleanup() {
	now := time.Now()
	for jti, expiresAt := range c.tokens {
		if !now.Before(expiresAt) {
			delete(c.tokens, jti)
		}
	}
}

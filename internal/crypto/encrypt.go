// Package crypto provides encryption and decryption for transport and storage.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const sessionKeyBytes = 32

var (
	// ErrTooShort is returned when ciphertext is shorter than the header.
	ErrTooShort = errors.New("ciphertext too short")
)

// KeyFromSecret derives a 32-byte AES key from a secret string.
func KeyFromSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// EncryptAES encrypts plaintext with AES-GCM. Output is base64(nonce||ciphertext).
func EncryptAES(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	out := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptAES decrypts base64(nonce||ciphertext) produced by EncryptAES.
func DecryptAES(encoded string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrTooShort
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}
	return plaintext, nil
}

// Encrypt encrypts plaintext with hybrid RSA-OAEP + AES-GCM.
// Format: 2-byte RSA length || RSA ciphertext || AES-GCM ciphertext.
func Encrypt(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	sessionKey := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt session key: %w", err)
	}
	if len(rsaCiphertext) > 0xFFFF {
		return nil, errors.New("RSA ciphertext too long")
	}

	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(len(rsaCiphertext)))
	out = append(out, rsaCiphertext...)

	nonce := make([]byte, aead.NonceSize())
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Decrypt decrypts hybrid RSA-OAEP + AES-GCM ciphertext.
func Decrypt(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	if len(ciphertext) < 2 {
		return nil, ErrTooShort
	}
	rsaLen := int(binary.BigEndian.Uint16(ciphertext[:2]))
	if len(ciphertext) < rsaLen+2 {
		return nil, ErrTooShort
	}

	rsaCiphertext := ciphertext[2 : rsaLen+2]
	aesCiphertext := ciphertext[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, rsaCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt session key: %w", err)
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, aesCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}
	return plaintext, nil
}

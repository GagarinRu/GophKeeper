package crypto_test

import (
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	publicPath, privatePath := crypto.WriteTestKeyPair(t, dir)

	pub, err := crypto.LoadPublicKey(publicPath)
	require.NoError(t, err)
	priv, err := crypto.LoadPrivateKey(privatePath)
	require.NoError(t, err)

	plaintext := []byte(`{"login":"u","password":"p"}`)
	ciphertext, err := crypto.Encrypt(plaintext, pub)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	decrypted, err := crypto.Decrypt(ciphertext, priv)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestEncryptAESRoundTrip(t *testing.T) {
	key := crypto.KeyFromSecret("test-secret")
	plain := []byte("secret payload")
	enc, err := crypto.EncryptAES(plain, key)
	require.NoError(t, err)
	dec, err := crypto.DecryptAES(enc, key)
	require.NoError(t, err)
	require.Equal(t, plain, dec)
}

func TestKeyFromSecret(t *testing.T) {
	key := crypto.KeyFromSecret("jwt")
	require.Len(t, key, 32)
}

func TestEncryptNilKey(t *testing.T) {
	_, err := crypto.Encrypt([]byte("test"), nil)
	require.Error(t, err)
}

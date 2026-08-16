package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestLoadPublicKeyErrors(t *testing.T) {
	_, err := crypto.LoadPublicKey("/nonexistent/path.pem")
	require.Error(t, err)

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badPath, []byte("not pem"), 0o600))
	_, err = crypto.LoadPublicKey(badPath)
	require.Error(t, err)
}

func TestLoadPrivateKeyErrors(t *testing.T) {
	_, err := crypto.LoadPrivateKey("/nonexistent/private.pem")
	require.Error(t, err)

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badPath, []byte("garbage"), 0o600))
	_, err = crypto.LoadPrivateKey(badPath)
	require.Error(t, err)
}

func TestDecryptAESInvalid(t *testing.T) {
	key := crypto.KeyFromSecret("test")
	_, err := crypto.DecryptAES("short", key)
	require.Error(t, err)
}

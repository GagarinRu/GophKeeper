package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WriteTestKeyPair generates an RSA key pair and writes cert.pem and private.pem files.
func WriteTestKeyPair(t *testing.T, dir string) (publicPath, privatePath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	var privatePEM bytes.Buffer
	if err := pem.Encode(&privatePEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		t.Fatalf("encode private key: %v", err)
	}

	publicPath = filepath.Join(dir, "cert.pem")
	privatePath = filepath.Join(dir, "private.pem")
	if err := os.WriteFile(publicPath, certPEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(privatePath, privatePEM.Bytes(), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return publicPath, privatePath
}

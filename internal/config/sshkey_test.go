package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

const testAuthorizedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7+pI/9vwrbcLsGL6r2TQN+LYnpJV0JIkgOrNssWYPb test"

func TestParseSSHKeyFingerprint(t *testing.T) {
	key, err := ParseSSHKey("SHA256:abc123")
	require.NoError(t, err)
	require.Equal(t, "SHA256:abc123", key.Fingerprint)
}

func TestParseSSHKeyLiteralPublicKey(t *testing.T) {
	key, err := ParseSSHKey(testAuthorizedKey)
	require.NoError(t, err)
	require.NotNil(t, key.PublicKey)
}

func TestParseSSHKeyPathExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.WriteFile(filepath.Join(home, "id_ed25519.pub"), []byte(testAuthorizedKey), 0o600))

	key, err := ParseSSHKey("~/id_ed25519.pub")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, "id_ed25519.pub"), key.Path)
	require.NotNil(t, key.PublicKey)
}

func TestParseSSHKeyPrivateKeyPath(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gossh.MarshalPrivateKey(private, "test")
	require.NoError(t, err)
	privateKey := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(path, privateKey, 0o600))

	key, err := ParseSSHKey(path)
	require.NoError(t, err)
	require.NotNil(t, key.Signer)
	require.Equal(t, gossh.FingerprintSHA256(key.PublicKey), gossh.FingerprintSHA256(key.Signer.PublicKey()))
}

func TestValidateRejectsProxyKeyFingerprint(t *testing.T) {
	cfg := Config{Routes: []RouteEntry{{Proxy: ProxyEntry{Host: "example.test:22", Key: SSHKey{Fingerprint: "SHA256:abc123"}}}}}

	err := cfg.validate()
	require.ErrorContains(t, err, "proxy.key must be a literal key or path, not a fingerprint")
}

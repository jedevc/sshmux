package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

type SSHKey struct {
	Raw         string
	Path        string
	Fingerprint string
	PublicKey   gossh.PublicKey
	Signer      gossh.Signer
}

func (k *SSHKey) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := ParseSSHKey(raw)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

func ParseSSHKey(raw string) (SSHKey, error) {
	key := SSHKey{Raw: raw}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return key, nil
	}
	if strings.HasPrefix(raw, "SHA256:") {
		key.Fingerprint = raw
		return key, nil
	}

	data := []byte(raw)
	if !looksLikeSSHKeyLiteral(raw) {
		path := expandHome(raw)
		fileData, err := os.ReadFile(path)
		if err != nil {
			return SSHKey{}, fmt.Errorf("read ssh key %q: %w", raw, err)
		}
		key.Path = path
		data = fileData
	}

	if signer, err := gossh.ParsePrivateKey(data); err == nil {
		key.Signer = signer
		key.PublicKey = signer.PublicKey()
		return key, nil
	}
	if pub, _, _, _, err := gossh.ParseAuthorizedKey(data); err == nil {
		key.PublicKey = pub
		return key, nil
	}
	pub, err := gossh.ParsePublicKey(data)
	if err != nil {
		return SSHKey{}, fmt.Errorf("parse ssh key: %w", err)
	}
	key.PublicKey = pub
	return key, nil
}

func (k SSHKey) IsZero() bool {
	return k.Raw == "" && k.Path == "" && k.Fingerprint == "" && k.PublicKey == nil && k.Signer == nil
}

func looksLikeSSHKeyLiteral(value string) bool {
	return strings.Contains(value, "-----BEGIN ") || strings.HasPrefix(value, "ssh-") || strings.HasPrefix(value, "ecdsa-") || strings.HasPrefix(value, "sk-")
}

func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return home + path[1:]
}

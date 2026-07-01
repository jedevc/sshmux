package main

import (
	"cmp"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
)

var (
	guestHostKey     ssh.Signer
	guestAllowKey    ssh.PublicKey
	guestIdleTimeout time.Duration
	guestShell       string
	guestHome        string
)

func init() {
	var err error
	guestHostKey, err = parseHostKey()
	if err != nil {
		fatalConfig(err)
	}
	guestAllowKey, err = parseAllowKey()
	if err != nil {
		fatalConfig(err)
	}
	guestIdleTimeout, err = parseIdleTimeout()
	if err != nil {
		fatalConfig(err)
	}
	guestShell = cmp.Or(os.Getenv("SHELL"), defaultShell)
	guestHome = cmp.Or(os.Getenv("HOME"), defaultHome)
}

func parseHostKey() (ssh.Signer, error) {
	hostKeyPEM := strings.TrimSpace(os.Getenv("GUEST_HOST_KEY"))
	if hostKeyPEM == "" {
		return nil, fmt.Errorf("GUEST_HOST_KEY env var is not set")
	}
	hostKey, err := gossh.ParsePrivateKey([]byte(hostKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse GUEST_HOST_KEY: %w", err)
	}
	return hostKey, nil
}

func parseAllowKey() (ssh.PublicKey, error) {
	allowKeyLine := strings.TrimSpace(os.Getenv("GUEST_ALLOW_KEY"))
	if allowKeyLine == "" {
		return nil, fmt.Errorf("GUEST_ALLOW_KEY env var is not set")
	}
	allowKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(allowKeyLine))
	if err != nil {
		return nil, fmt.Errorf("parse GUEST_ALLOW_KEY: %w", err)
	}
	return allowKey, nil
}

func parseIdleTimeout() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv("GUEST_IDLE_TIMEOUT"))
	if raw == "" {
		return defaultGuestIdleTimeout, nil
	}
	idleTimeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse GUEST_IDLE_TIMEOUT: %w", err)
	}
	if idleTimeout <= 0 {
		return 0, fmt.Errorf("GUEST_IDLE_TIMEOUT must be positive")
	}
	return idleTimeout, nil
}

func fatalConfig(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "guest config: %v\n", err)
	os.Exit(1)
}

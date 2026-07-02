package server

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"charm.land/log/v2"
	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshmux/internal/cloud"
	"sshmux/internal/config"
)

func cloudSession(s ssh.Session, provider cloud.Provider) error {
	client, cleanup, err := provider.Dial(s.Context(), s)
	if err != nil {
		return err
	}
	defer cleanup()
	return proxySSHSession(s, client)
}

func proxySession(s ssh.Session, route config.RouteEntry) error {
	client, err := dialBackend(s, route)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return proxySSHSession(s, client)
}

func proxySSHSession(s ssh.Session, client *gossh.Client) error {
	backend, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new backend session: %w", err)
	}
	defer func() { _ = backend.Close() }()

	backend.Stdin = s
	backend.Stdout = s
	backend.Stderr = s.Stderr()
	for _, env := range s.Environ() {
		k, v, ok := strings.Cut(env, "=")
		if ok {
			_ = backend.Setenv(k, v)
		}
	}

	if pty, winCh, ok := sessionPty(s); ok {
		log.Info("Forwarding PTY", "term", pty.Term, "height", pty.Window.Height, "width", pty.Window.Width)
		if err := backend.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, pty.Modes); err != nil {
			return fmt.Errorf("request backend pty: %w", err)
		}
		go func() {
			for win := range winCh {
				_ = backend.WindowChange(win.Height, win.Width)
			}
		}()
	} else {
		log.Info("Forwarding without PTY")
	}

	sigCh := make(chan ssh.Signal, 16)
	s.Signals(sigCh)
	defer s.Signals(nil)
	go func() {
		for sig := range sigCh {
			_ = backend.Signal(gossh.Signal(sig))
		}
	}()

	if raw := s.RawCommand(); raw != "" {
		if err := backend.Start(raw); err != nil {
			return fmt.Errorf("start backend command: %w", err)
		}
	} else if err := backend.Shell(); err != nil {
		return fmt.Errorf("start backend shell: %w", err)
	}
	return backend.Wait()
}

func dialBackend(s ssh.Session, route config.RouteEntry) (*gossh.Client, error) {
	user := route.Proxy.User
	if user == "" {
		user = s.User()
	}
	authMethods, err := proxyAuthMethods(route)
	if err != nil {
		return nil, err
	}
	hostKeyCallback, err := proxyHostKeyCallback(route.Proxy.HostKey)
	if err != nil {
		return nil, err
	}
	client, err := gossh.Dial("tcp", route.Proxy.Host, &gossh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("dial backend %s: %w", route.Proxy.Host, err)
	}
	return client, nil
}

func proxyAuthMethods(route config.RouteEntry) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	if !route.Proxy.Key.IsZero() {
		signer, err := proxySigner(route.Proxy.Key)
		if err != nil {
			return nil, err
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if route.Proxy.Password != "" {
		methods = append(methods, gossh.Password(route.Proxy.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("proxy route requires proxy.key or proxy.password")
	}
	return methods, nil
}

func proxySigner(key config.SSHKey) (gossh.Signer, error) {
	if key.Fingerprint != "" {
		return nil, fmt.Errorf("proxy key must be a literal key or path, not a fingerprint")
	}
	if key.Signer == nil {
		return nil, fmt.Errorf("proxy key must be a private key")
	}
	return key.Signer, nil
}

func proxyHostKeyCallback(hostKeys []string) (gossh.HostKeyCallback, error) {
	if len(hostKeys) == 0 {
		return gossh.InsecureIgnoreHostKey(), nil
	}
	keys := make([]gossh.PublicKey, 0, len(hostKeys))
	for _, hostKey := range hostKeys {
		key, err := parseProxyPublicKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("parse proxy host key: %w", err)
		}
		keys = append(keys, key)
	}
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		for _, allowed := range keys {
			if ssh.KeysEqual(key, allowed) {
				return nil
			}
		}
		return fmt.Errorf("remote host key does not match pinned proxy host keys")
	}, nil
}

func parseProxyPublicKey(key string) (gossh.PublicKey, error) {
	data := []byte(key)
	if !strings.Contains(key, "ssh-") {
		var err error
		data, err = os.ReadFile(key)
		if err != nil {
			return nil, fmt.Errorf("read proxy host key: %w", err)
		}
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey(data)
	if err == nil {
		return pub, nil
	}
	return gossh.ParsePublicKey(data)
}

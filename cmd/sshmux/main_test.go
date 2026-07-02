package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/wish/v2"
	"charm.land/wish/v2/logging"
	"github.com/charmbracelet/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"sshmux/internal/cloud"
	"sshmux/internal/config"
	"sshmux/internal/server"
)

type Config = config.Config
type AuthEntry = config.AuthEntry
type RouteEntry = config.RouteEntry
type StringOrSlice = config.StringOrSlice
type Pattern = config.Pattern
type RunEntry = config.RunEntry
type ProxyEntry = config.ProxyEntry
type CloudEntry = config.CloudEntry
type Providers = cloud.Providers

var parsePattern = config.ParsePattern
var withPtyRequests = server.WithPtyRequests
var withAuth = server.WithAuth
var withSessionRoutingPolicy = server.WithSessionRoutingPolicy
var muxMiddleware = server.MuxMiddleware
var exitCode = server.ExitCode

func TestExecSimpleCmd(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("alice"),
			Role:     "user",
			Run:      RunEntry{Cmd: "echo hello-world"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "alice", "ignored-arg")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "hello-world")
}

func TestExecSimpleCmdWithPTY(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("slides"),
			Role:     "user",
			Run:      RunEntry{Cmd: "printf 'slide output'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPTY(t, ts, privKey, "slides")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "slide output")
}

func TestExecConfiguredPTY(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"admin"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("editor"),
			Role:     "admin",
			Run:      RunEntry{Cmd: "printf 'pty output'", Pty: boolPtr(true)},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPTY(t, ts, privKey, "editor")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "pty output")
}

func TestExecConfiguredNoPTYIgnoresClientPTY(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"admin"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("plain"),
			Role:     "admin",
			Run:      RunEntry{Cmd: "if [ -t 0 ]; then printf pty; else printf no-pty; fi", Pty: boolPtr(false)},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPTY(t, ts, privKey, "plain")
	assert.Equal(t, 0, code)
	assert.Equal(t, "no-pty", stdout)
}

func TestExecMatchedByRawKey(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")

	cfg := &Config{
		Auth: []AuthEntry{
			{Key: sshKey(t, pubLine), Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("bob"),
			Run:      RunEntry{Cmd: "printf 'key-matched'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "bob")
	assert.Equal(t, 0, code)
	assert.Equal(t, "key-matched", stdout)
}

func TestRunCommandReceivesSSHMuxEnv(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")

	cfg := &Config{
		Auth: []AuthEntry{
			{Key: sshKey(t, pubLine), Role: StringOrSlice{"user", "admin"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("bob"),
			Role:     "user",
			Run:      RunEntry{Cmd: `printf '%s|%s|%s' "$SSHMUX_USERNAME" "$SSHMUX_COMMAND" "$SSHMUX_ROLES"`},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "bob", "client command")
	assert.Equal(t, 0, code)
	assert.Equal(t, "bob|client command|user,admin", stdout)
}

func TestExecMatchedByPassword(t *testing.T) {
	cfg := &Config{
		Auth: []AuthEntry{
			{Password: "secret", Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("password-user"),
			Role:     "user",
			Run:      RunEntry{Cmd: "printf 'password-matched'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPassword(t, ts, "password-user", "secret")
	assert.Equal(t, 0, code)
	assert.Equal(t, "password-matched", stdout)
}

func TestPasswordAuthNotAdvertisedForKeyOnlyRoute(t *testing.T) {
	cfg := &Config{
		Auth: []AuthEntry{
			{Password: "secret", Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("admin"),
			Role:     "admin",
			Run:      RunEntry{Cmd: "printf 'admin'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, stderr, code := sshRunPassword(t, ts, "admin", "secret")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "Permission denied (publickey)")
}

func TestExecMatchedByHashedPassword(t *testing.T) {
	cfg := &Config{
		Auth: []AuthEntry{
			{Password: "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("password-user"),
			Role:     "user",
			Run:      RunEntry{Cmd: "printf 'hashed-password-matched'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPassword(t, ts, "password-user", "secret")
	assert.Equal(t, 0, code)
	assert.Equal(t, "hashed-password-matched", stdout)
}

func TestExecWildcardUsername(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("slide-*"),
			Role:     "user",
			Run:      RunEntry{Cmd: "printf 'wildcard-matched'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "slide-deck")
	assert.Equal(t, 0, code)
	assert.Equal(t, "wildcard-matched", stdout)
}

func TestExecRegexUsername(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("/^deck-[0-9]+$/"),
			Role:     "user",
			Run:      RunEntry{Cmd: "printf 'regex-matched'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "deck-42")
	assert.Equal(t, 0, code)
	assert.Equal(t, "regex-matched", stdout)
}

func TestExecNegatedUsername(t *testing.T) {
	cfg := &Config{
		Routes: []RouteEntry{{
			Username: pattern("!admin"),
			Run:      RunEntry{Cmd: "printf 'not-admin'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "guest")
	assert.Equal(t, 0, code)
	assert.Equal(t, "not-admin", stdout)

	_, stderr, code := sshRunNoAuth(t, ts, "admin")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "Permission denied")
}

func TestExecPublicRoute(t *testing.T) {
	cfg := &Config{
		Routes: []RouteEntry{{
			Username: pattern("guest"),
			Run:      RunEntry{Cmd: "echo anyone-welcome"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "guest")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "anyone-welcome")
}

func TestPasswordAuthNotAdvertisedForPublicRoute(t *testing.T) {
	cfg := &Config{
		Auth: []AuthEntry{
			{Password: "secret", Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("guest"),
			Run:      RunEntry{Cmd: "printf 'public'"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunPassword(t, ts, "guest", "secret")
	assert.Equal(t, 0, code)
	assert.Equal(t, "public", stdout)
}

func TestExecNoMatchingRoute(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("alice"),
			Run:      RunEntry{Cmd: "echo hi"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, _, code := sshRun(t, ts, privKey, "nobody")
	assert.NotEqual(t, 0, code)
}

func TestExecRoleRestrictionAllowed(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"admin"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("admin"),
			Role:     "admin",
			Run:      RunEntry{Cmd: "echo admin-only"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "admin")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "admin-only")
}

func TestExecRoleRestrictionDenied(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("admin"),
			Role:     "admin",
			Run:      RunEntry{Cmd: "echo admin-only"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, _, code := sshRun(t, ts, privKey, "admin")
	assert.NotEqual(t, 0, code)
}

func TestExecCmdExitCode(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{{
			Username: pattern("alice"),
			Run:      RunEntry{Cmd: "exit 42"},
		}},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, _, code := sshRun(t, ts, privKey, "alice")
	assert.Equal(t, 42, code)
}

func TestExecMultipleRoutes(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user", "admin"}},
		},
		Routes: []RouteEntry{
			{Username: pattern("alice"), Role: "admin", Run: RunEntry{Cmd: "echo first"}},
			{Username: pattern("alice"), Role: "user", Run: RunEntry{Cmd: "echo second"}},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "alice")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "first")
	assert.NotContains(t, stdout, "second")
}

func TestUsernameRoutingIgnoresCommand(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user"}},
		},
		Routes: []RouteEntry{
			{
				Username: pattern("foo"),
				Role:     "user",
				Run:      RunEntry{Cmd: "printf first"},
			},
			{
				Username: pattern("foo"),
				Role:     "user",
				Run:      RunEntry{Cmd: "printf second"},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "foo", "ignored-command")
	assert.Equal(t, 0, code)
	assert.Equal(t, "first", stdout)
}

func TestProtectedCandidateRequiresAuthBeforeUsernameRouting(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"admin"}},
		},
		Routes: []RouteEntry{
			{
				Username: pattern("*"),
				Run:      RunEntry{Cmd: "printf public"},
			},
			{
				Username: pattern("admin"),
				Role:     "admin",
				Run:      RunEntry{Cmd: "printf admin"},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, stderr, code := sshRunNoAuth(t, ts, "admin")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "Permission denied")

	stdout, _, code := sshRun(t, ts, privKey, "admin")
	assert.Equal(t, 0, code)
	assert.Equal(t, "public", stdout)
}

func TestProtectedRouteBeforePublicFallbackUsesKeyRoles(t *testing.T) {
	dir := t.TempDir()
	privKey, pubLine := generateKey(t, dir, "client")
	fp := fingerprintFromPub(t, pubLine)

	cfg := &Config{
		Auth: []AuthEntry{
			{Fingerprint: fp, Role: StringOrSlice{"user", "admin"}},
		},
		Routes: []RouteEntry{
			{
				Username: pattern("nvim"),
				Role:     "admin",
				Run:      RunEntry{Cmd: "printf nvim"},
			},
			{
				Username: pattern("!root", "!admin"),
				Run:      RunEntry{Cmd: "printf license"},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRun(t, ts, privKey, "nvim")
	assert.Equal(t, 0, code)
	assert.Equal(t, "nvim", stdout)

	_, stderr, code := sshRunNoAuth(t, ts, "nvim")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "Permission denied")
}

func TestPrivilegedUserWithoutPublicRouteRejectedAtAuth(t *testing.T) {
	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("talk"),
				Run:      RunEntry{Cmd: "printf talk"},
			},
			{
				Username: pattern("admin"),
				Role:     "admin",
				Run:      RunEntry{Cmd: "printf admin"},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	_, stderr, code := sshRunNoAuth(t, ts, "admin")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, "Permission denied")
}

func TestProxyWithBackendPassword(t *testing.T) {
	backend := newBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("proxy-user"),
				Proxy: ProxyEntry{
					Host:     backend.addr,
					Password: "backend-secret",
				},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "proxy-user", "printf proxied-password")
	assert.Equal(t, 0, code)
	assert.Equal(t, "proxied-password", stdout)
}

func TestProxyWithBackendKey(t *testing.T) {
	dir := t.TempDir()
	proxyKey, proxyPub := generateKey(t, dir, "proxy-client")
	backend := newBackendServer(t, backendAuth{publicKey: proxyPub})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("proxy-user"),
				Proxy: ProxyEntry{
					Host: backend.addr,
					Key:  sshKey(t, proxyKey),
				},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "proxy-user", "printf proxied-key")
	assert.Equal(t, 0, code)
	assert.Equal(t, "proxied-key", stdout)
}

func TestProxyWithPinnedHostKey(t *testing.T) {
	backend := newBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("proxy-user"),
				Proxy: ProxyEntry{
					Host:     backend.addr,
					Password: "backend-secret",
					HostKey:  StringOrSlice{filepath.Join(backend.tmpDir, "host_ed25519.pub")},
				},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "proxy-user", "printf proxied-host-key")
	assert.Equal(t, 0, code)
	assert.Equal(t, "proxied-host-key", stdout)
}

func TestProxyWithMultiplePinnedHostKeys(t *testing.T) {
	backend := newBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()
	_, decoyPub := generateKey(t, backend.tmpDir, "decoy_ed25519")

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("proxy-user"),
				Proxy: ProxyEntry{
					Host:     backend.addr,
					Password: "backend-secret",
					HostKey: StringOrSlice{
						decoyPub,
						filepath.Join(backend.tmpDir, "host_ed25519.pub"),
					},
				},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "proxy-user", "printf proxied-host-keys")
	assert.Equal(t, 0, code)
	assert.Equal(t, "proxied-host-keys", stdout)
}

func TestProxyRouteForwardsPTY(t *testing.T) {
	backend := newPTYDetectBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("proxy-user"),
				Proxy: ProxyEntry{
					Host:     backend.addr,
					Password: "backend-secret",
				},
			},
		},
	}

	ts := newTestServer(t, cfg)
	defer ts.stop()

	stdout, _, code := sshRunWithOptions(t, ts, "", "proxy-user", []string{"-tt"}, "ignored")
	assert.Equal(t, 0, code)
	assert.Equal(t, "pty=true", stdout)
}

func TestCloudRouteForwardsPTY(t *testing.T) {
	backend := newPTYDetectBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("cloud-user"),
				Cloud:    CloudEntry{Provider: "unikraft"},
			},
		},
	}
	ts := newTestServerWithProviders(t, cfg, Providers{
		0: testProvider{addr: backend.addr, password: "backend-secret"},
	})
	defer ts.stop()

	stdout, _, code := sshRunWithOptions(t, ts, "", "cloud-user", []string{"-tt"}, "ignored")
	assert.Equal(t, 0, code)
	assert.Equal(t, "pty=true", stdout)
}

func TestCloudRouteDoesNotForwardPTYWhenCallerHasNone(t *testing.T) {
	backend := newPTYDetectBackendServer(t, backendAuth{password: "backend-secret"})
	defer backend.stop()

	cfg := &Config{
		Routes: []RouteEntry{
			{
				Username: pattern("cloud-user"),
				Cloud:    CloudEntry{Provider: "unikraft"},
			},
		},
	}
	ts := newTestServerWithProviders(t, cfg, Providers{
		0: testProvider{addr: backend.addr, password: "backend-secret"},
	})
	defer ts.stop()

	stdout, _, code := sshRunNoAuth(t, ts, "cloud-user", "ignored")
	assert.Equal(t, 0, code)
	assert.Equal(t, "pty=false", stdout)
}

type testServer struct {
	addr   string
	stop   func()
	tmpDir string
}

type backendAuth struct {
	password  string
	publicKey string
}

type testProvider struct {
	addr     string
	password string
}

func (p testProvider) Dial(_ context.Context, s ssh.Session) (*gossh.Client, func(), error) {
	client, err := gossh.Dial("tcp", p.addr, &gossh.ClientConfig{
		User: s.User(),
		Auth: []gossh.AuthMethod{
			gossh.Password(p.password),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	return client, func() { _ = client.Close() }, nil
}

func newBackendServer(t *testing.T, auth backendAuth) *testServer {
	t.Helper()

	tmpDir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var options []ssh.Option
	options = append(options,
		wish.WithAddress(ln.Addr().String()),
		wish.WithHostKeyPath(filepath.Join(tmpDir, "host_ed25519")),
		func(srv *ssh.Server) error {
			srv.Handler = func(s ssh.Session) {
				cmd := exec.CommandContext(s.Context(), "sh", "-c", s.RawCommand())
				cmd.Stdin = s
				cmd.Stdout = s
				cmd.Stderr = s.Stderr()
				if err := cmd.Run(); err != nil {
					_ = s.Exit(exitCode(err))
					return
				}
				_ = s.Exit(0)
			}
			return nil
		},
	)
	if auth.password != "" {
		options = append(options, wish.WithPasswordAuth(func(_ ssh.Context, password string) bool {
			return password == auth.password
		}))
	}
	if auth.publicKey != "" {
		allowed, _, _, _, err := gossh.ParseAuthorizedKey([]byte(auth.publicKey))
		require.NoError(t, err)
		options = append(options, wish.WithPublicKeyAuth(func(_ ssh.Context, key ssh.PublicKey) bool {
			return ssh.KeysEqual(key, allowed)
		}))
	}

	s, err := wish.NewServer(options...)
	if err != nil {
		require.NoError(t, ln.Close())
		require.NoError(t, err, "backend wish.NewServer")
	}

	go func() {
		if err := s.Serve(ln); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			_ = err
		}
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}

	return &testServer{addr: ln.Addr().String(), stop: stop, tmpDir: tmpDir}
}

func newPTYDetectBackendServer(t *testing.T, auth backendAuth) *testServer {
	t.Helper()

	tmpDir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	options := []ssh.Option{
		wish.WithAddress(ln.Addr().String()),
		wish.WithHostKeyPath(filepath.Join(tmpDir, "host_ed25519")),
		ssh.AllocatePty(),
		func(srv *ssh.Server) error {
			srv.Handler = func(s ssh.Session) {
				_, _, ok := s.Pty()
				if ok {
					_, _ = s.Write([]byte("pty=true"))
				} else {
					_, _ = s.Write([]byte("pty=false"))
				}
				_ = s.Exit(0)
			}
			return nil
		},
	}
	if auth.password != "" {
		options = append(options, wish.WithPasswordAuth(func(_ ssh.Context, password string) bool {
			return password == auth.password
		}))
	}

	s, err := wish.NewServer(options...)
	if err != nil {
		require.NoError(t, ln.Close())
		require.NoError(t, err, "wish.NewServer")
	}

	go func() {
		if err := s.Serve(ln); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			_ = err
		}
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}

	return &testServer{addr: ln.Addr().String(), stop: stop, tmpDir: tmpDir}
}

func newTestServer(t *testing.T, cfg *Config) *testServer {
	return newTestServerWithProviders(t, cfg, nil)
}

func newTestServerWithProviders(t *testing.T, cfg *Config, providers Providers) *testServer {
	t.Helper()

	tmpDir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	hostKey := filepath.Join(tmpDir, "host_ed25519")
	s, err := wish.NewServer(
		wish.WithAddress(ln.Addr().String()),
		wish.WithHostKeyPath(hostKey),
		withPtyRequests(),
		withAuth(cfg),
		withSessionRoutingPolicy(cfg),
		wish.WithMiddleware(
			muxMiddleware(cfg, providers),
			logging.Middleware(),
		),
	)
	if err != nil {
		require.NoError(t, ln.Close())
		require.NoError(t, err, "wish.NewServer")
	}

	go func() {
		if err := s.Serve(ln); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			_ = err
		}
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}

	return &testServer{addr: ln.Addr().String(), stop: stop, tmpDir: tmpDir}
}

func generateKey(t *testing.T, dir, name string) (privPath, pubLine string) {
	t.Helper()

	privPath = filepath.Join(dir, name)
	pubPath := privPath + ".pub"
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privPath, "-C", name).CombinedOutput()
	require.NoError(t, err, "ssh-keygen: %s", out)

	pubBytes, err := os.ReadFile(pubPath)
	require.NoError(t, err, "read pubkey")

	return privPath, strings.TrimSpace(string(pubBytes))
}

func fingerprintFromPub(t *testing.T, pubLine string) string {
	t.Helper()

	pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubLine))
	require.NoError(t, err, "parse authorized key")

	return gossh.FingerprintSHA256(pk)
}

func sshKey(t *testing.T, raw string) config.SSHKey {
	t.Helper()
	key, err := config.ParseSSHKey(raw)
	require.NoError(t, err, "parse ssh key")
	return key
}

func pattern(parts ...string) Pattern {
	pattern, err := parsePattern(parts)
	if err != nil {
		panic(err)
	}
	return pattern
}

func boolPtr(value bool) *bool {
	return &value
}

func sshRun(t *testing.T, ts *testServer, privKey, user string, remoteArgs ...string) (stdout, stderr string, code int) {
	return sshRunWithOptions(t, ts, privKey, user, nil, remoteArgs...)
}

func sshRunNoAuth(t *testing.T, ts *testServer, user string, remoteArgs ...string) (stdout, stderr string, code int) {
	return sshRunWithOptions(t, ts, "", user, nil, remoteArgs...)
}

func sshRunPTY(t *testing.T, ts *testServer, privKey, user string, remoteArgs ...string) (stdout, stderr string, code int) {
	return sshRunWithOptions(t, ts, privKey, user, []string{"-tt"}, remoteArgs...)
}

func sshRunPassword(t *testing.T, ts *testServer, user, password string, remoteArgs ...string) (stdout, stderr string, code int) {
	t.Helper()

	_, port, err := net.SplitHostPort(ts.addr)
	require.NoError(t, err)

	askpass := filepath.Join(ts.tmpDir, "askpass.sh")
	require.NoError(t, os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' \"$SSHMUX_PASSWORD\"\n"), 0o700))

	knownHosts := filepath.Join(ts.tmpDir, "known_hosts")
	args := []string{
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=yes",
		"-o", "PreferredAuthentications=password",
		"-o", "NumberOfPasswordPrompts=1",
		user + "@127.0.0.1",
	}
	args = append(args, remoteArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = append(os.Environ(),
		"DISPLAY=sshmux-test",
		"SSH_ASKPASS="+askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"SSHMUX_PASSWORD="+password,
	)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout, stderr, exitErr.ExitCode()
		}
		require.NoError(t, err, "ssh password process error\nstderr: %s", stderr)
	}

	return stdout, stderr, 0
}

func sshRunWithOptions(t *testing.T, ts *testServer, privKey, user string, extraOptions []string, remoteArgs ...string) (stdout, stderr string, code int) {
	t.Helper()

	_, port, err := net.SplitHostPort(ts.addr)
	require.NoError(t, err)

	knownHosts := filepath.Join(ts.tmpDir, "known_hosts")
	args := append([]string{}, extraOptions...)
	if privKey != "" {
		args = append(args, "-i", privKey)
	}
	args = append(args, []string{
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		user + "@127.0.0.1",
	}...)
	args = append(args, remoteArgs...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout, stderr, exitErr.ExitCode()
		}
		require.NoError(t, err, "ssh process error\nstderr: %s", stderr)
	}

	return stdout, stderr, 0
}

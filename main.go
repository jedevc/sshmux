package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"charm.land/wish/v2/logging"
	"github.com/alecthomas/kong"
	"github.com/charmbracelet/ssh"
	creackpty "github.com/creack/pty"
	htpasswd "github.com/tg123/go-htpasswd"
	gossh "golang.org/x/crypto/ssh"
)

// CLI defines the command-line interface parsed by Kong.
var CLI struct {
	Host   string `arg:"" optional:"" default:"0.0.0.0:22" help:"Address to listen on (host:port)."`
	Config string `short:"c" required:"" help:"Path to the YAML config file."`
}

func main() {
	if err := run(); err != nil {
		log.Error("Failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	kong.Parse(&CLI,
		kong.Name("sshmux"),
		kong.Description("A simple SSH multiplexer."),
		kong.UsageOnError(),
	)

	cfg, err := LoadConfig(CLI.Config)
	if err != nil {
		return err
	}
	providers, err := buildProviders(cfg)
	if err != nil {
		return err
	}

	s, err := wish.NewServer(
		wish.WithAddress(CLI.Host),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		withPtyRequests(),
		withAuth(cfg),
		withSessionRoutingPolicy(cfg),
		wish.WithMiddleware(
			muxMiddleware(cfg, providers),
			logging.Middleware(),
		),
	)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(done)
	log.Info("Starting SSH muxer", "addr", CLI.Host)

	serverErr := make(chan error, 1)

	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-done:
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}

	log.Info("Shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}

func withSessionRoutingPolicy(cfg *Config) ssh.Option {
	return func(srv *ssh.Server) error {
		srv.SessionRequestCallback = func(s ssh.Session, _ string) bool {
			return findRoute(cfg, s.User(), G(s.Context())) != nil
		}
		return nil
	}
}

type ptyRequestKey struct {
	session ssh.Session
}

func withPtyRequests() ssh.Option {
	return func(srv *ssh.Server) error {
		srv.PtyHandler = func(ctx ssh.Context, s ssh.Session, pty ssh.Pty) (func() error, error) {
			// Proxy routes need the client's PTY metadata so it can be forwarded to
			// the backend, but they must not allocate an intermediate PTY or use
			// ssh.EmulatePty(), which rewrites output newlines and breaks transparent
			// terminal proxying. Local run.pty routes allocate their own PTY later.
			key := ptyRequestKey{session: s}
			ctx.SetValue(key, pty)
			return func() error {
				ctx.SetValue(key, nil)
				return nil
			}, nil
		}
		return nil
	}
}

func sessionPty(s ssh.Session) (ssh.Pty, <-chan ssh.Window, bool) {
	pty, winCh, ok := s.Pty()
	if ok {
		return pty, winCh, true
	}
	pty, ok = s.Context().Value(ptyRequestKey{session: s}).(ssh.Pty)
	if !ok {
		return ssh.Pty{}, winCh, false
	}
	return pty, winCh, true
}

func withAuth(cfg *Config) ssh.Option {
	return func(s *ssh.Server) error {
		s.ServerConfigCallback = func(ctx ssh.Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{
				NoClientAuth: true,
				NoClientAuthCallback: func(conn gossh.ConnMetadata) (*gossh.Permissions, error) {
					next, public := authCallbacks(ctx, cfg, conn.User())
					if public {
						return &gossh.Permissions{}, nil
					}
					return nil, &gossh.PartialSuccessError{Next: next}
				},
			}
		}
		return nil
	}
}

func authCallbacks(ctx ssh.Context, cfg *Config, username string) (gossh.ServerAuthCallbacks, bool) {
	candidates := usernameMatchingRoutes(cfg, username)
	if len(candidates) > 0 && routesArePublic(candidates) {
		return gossh.ServerAuthCallbacks{}, true
	}

	callbacks := gossh.ServerAuthCallbacks{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			roles := publicKeyRoles(cfg, key)
			if !canReachRoute(cfg, username, roles) || !applyRoles(ctx, roles) {
				return nil, fmt.Errorf("permission denied")
			}
			return publicKeyPermissions(key), nil
		},
	}
	if passwordAllowedForUsername(cfg, username) {
		callbacks.PasswordCallback = func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			roles := passwordRoles(cfg, string(password))
			if !canReachRoute(cfg, username, roles) || !applyRoles(ctx, roles) {
				return nil, fmt.Errorf("permission denied")
			}
			return &gossh.Permissions{}, nil
		}
	}
	if len(candidates) == 0 {
		return callbacks, false
	}
	return callbacks, false
}

func usernameMatchingRoutes(cfg *Config, username string) []RouteEntry {
	var routes []RouteEntry
	for _, route := range cfg.Routes {
		if route.Username.Match(username) {
			routes = append(routes, route)
		}
	}
	return routes
}

func routesArePublic(routes []RouteEntry) bool {
	for _, route := range routes {
		if route.Role != "" {
			return false
		}
	}
	return true
}

func publicKeyRoles(cfg *Config, key ssh.PublicKey) []string {
	fp := gossh.FingerprintSHA256(key)
	var roles []string
	for _, auth := range cfg.Auth {
		if auth.Fingerprint != "" && auth.Fingerprint == fp {
			roles = append(roles, auth.Role...)
			continue
		}
		if auth.Key != "" {
			allowedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(auth.Key))
			if err == nil && ssh.KeysEqual(key, allowedKey) {
				roles = append(roles, auth.Role...)
			}
		}
	}
	return roles
}

func passwordRoles(cfg *Config, password string) []string {
	var roles []string
	for _, auth := range cfg.Auth {
		if auth.Password != "" && matchPassword(auth.Password, password) {
			roles = append(roles, auth.Role...)
		}
	}
	return roles
}

func publicKeyPermissions(key gossh.PublicKey) *gossh.Permissions {
	return &gossh.Permissions{
		Extensions: map[string]string{
			"gliderlabs/ssh.PublicKey": base64.StdEncoding.EncodeToString(key.Marshal()),
		},
	}
}

func applyRoles(ctx ssh.Context, roles []string) bool {
	if len(roles) == 0 {
		return false
	}
	ContextWithRoles(ctx, roles)
	return true
}

func passwordAllowedForUsername(cfg *Config, username string) bool {
	passwordRoles := passwordAuthRoles(cfg)
	if len(passwordRoles) == 0 {
		return false
	}
	for _, route := range cfg.Routes {
		if !route.Username.Match(username) {
			continue
		}
		if route.Role != "" && slices.Contains(passwordRoles, route.Role) {
			return true
		}
	}
	return false
}

func passwordAuthRoles(cfg *Config) []string {
	var roles []string
	for _, auth := range cfg.Auth {
		if auth.Password != "" {
			roles = append(roles, auth.Role...)
		}
	}
	return roles
}

func matchPassword(stored string, password string) bool {
	for _, parser := range htpasswd.DefaultSystems {
		parsed, err := parser(stored)
		if err != nil || parsed == nil {
			continue
		}
		return parsed.MatchesPassword(password)
	}
	return false
}

func canReachRoute(cfg *Config, username string, roles []string) bool {
	for _, route := range cfg.Routes {
		if route.Username.Match(username) && routeRoleAllowed(route, roles) {
			return true
		}
	}
	return false
}

// muxMiddleware returns a wish.Middleware that routes each session based on
// the config's routes list.
func muxMiddleware(cfg *Config, providerSets ...Providers) wish.Middleware {
	providers := Providers(nil)
	if len(providerSets) > 0 {
		providers = providerSets[0]
	}
	return func(_ ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			username := s.User()
			roles := G(s.Context())

			route, routeIndex := findRouteIndex(cfg, username, roles)
			if route != nil {
				if !routeRoleAllowed(*route, roles) {
					_, _ = fmt.Fprintf(s.Stderr(), "permission denied\r\n")
					_ = s.Exit(1)
					return
				}
				if route.Proxy.Host != "" {
					if err := proxySession(s, *route); err != nil {
						log.Error("Proxy error", "addr", route.Proxy.Host, "error", err)
						_, _ = fmt.Fprintf(s.Stderr(), "proxy error: %v\r\n", err)
						_ = s.Exit(exitCode(err))
					}
					return
				}
				if route.Cloud.Provider != "" {
					provider := providers[routeIndex]
					if provider == nil {
						_, _ = fmt.Fprintf(s.Stderr(), "cloud provider is not configured\r\n")
						_ = s.Exit(1)
						return
					}
					if err := cloudSession(s, provider); err != nil {
						log.Error("Cloud error", "provider", route.Cloud.Provider, "error", err)
						_, _ = fmt.Fprintf(s.Stderr(), "cloud error: %v\r\n", err)
						_ = s.Exit(exitCode(err))
					}
					return
				}
				if route.Run.Cmd != "" {
					if err := runCmd(s, route.Run.Cmd, route.Run.Pty); err != nil {
						log.Error("Command error", "cmd", route.Run.Cmd, "error", err)
						_ = s.Exit(exitCode(err))
						return
					}
					_ = s.Exit(0)
					return
				}
			}

			_ = s.Exit(1)
		}
	}
}

func findRoute(cfg *Config, username string, _ []string) *RouteEntry {
	route, _ := findRouteIndex(cfg, username, nil)
	return route
}

func findRouteIndex(cfg *Config, username string, _ []string) (*RouteEntry, int) {
	for i := range cfg.Routes {
		if matchesRouteSession(cfg.Routes[i], username) {
			return &cfg.Routes[i], i
		}
	}
	return nil, -1
}

func routeRoleAllowed(route RouteEntry, roles []string) bool {
	return route.Role == "" || slices.Contains(roles, route.Role)
}

func matchesRouteSession(route RouteEntry, username string) bool {
	return route.Username.Match(username)
}

// runCmd executes the configured command for the session.
func runCmd(s ssh.Session, command string, withPTY bool) error {
	cmd := exec.CommandContext(s.Context(), "sh", "-c", command)
	cmd.Env = append(os.Environ(), s.Environ()...)

	if withPTY {
		ptyReq, winCh, ok := sessionPty(s)
		if !ok {
			return fmt.Errorf("pty requested but client did not allocate one")
		}
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
		ptyFile, err := creackpty.StartWithSize(cmd, ptyWindowSize(ptyReq.Window))
		if err != nil {
			return fmt.Errorf("start pty cmd: %w", err)
		}

		done := make(chan struct{})
		defer close(done)
		go resizePty(ptyFile, winCh, done)

		go func() {
			_, _ = io.Copy(ptyFile, s)
		}()

		outputDone := make(chan struct{})
		go func() {
			defer close(outputDone)
			_, _ = io.Copy(s, ptyFile)
		}()

		waitErr := cmd.Wait()
		<-outputDone
		_ = ptyFile.Close()
		return waitErr
	}

	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cmd: %w", err)
	}
	return cmd.Wait()
}

func ptyWindowSize(win ssh.Window) *creackpty.Winsize {
	return &creackpty.Winsize{
		Rows: uint16(win.Height),
		Cols: uint16(win.Width),
		X:    uint16(win.WidthPixels),
		Y:    uint16(win.HeightPixels),
	}
}

func resizePty(ptyFile *os.File, winCh <-chan ssh.Window, done <-chan struct{}) {
	for {
		select {
		case win, ok := <-winCh:
			if !ok {
				return
			}
			_ = creackpty.Setsize(ptyFile, ptyWindowSize(win))
		case <-done:
			return
		}
	}
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	var sshExitErr *gossh.ExitError
	if errors.As(err, &sshExitErr) {
		return sshExitErr.ExitStatus()
	}
	return 1
}

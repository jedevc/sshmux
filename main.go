package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"slices"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"charm.land/wish/v2/logging"
	"github.com/alecthomas/kong"
	"github.com/charmbracelet/ssh"
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

	s, err := wish.NewServer(
		wish.WithAddress(CLI.Host),
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		ssh.AllocatePty(),
		withAuth(cfg),
		withSessionRoutingPolicy(cfg),
		wish.WithMiddleware(
			muxMiddleware(cfg),
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
			return findRoute(cfg, s.User(), G(s.Context()), s.RawCommand()) != nil
		}
		return nil
	}
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
	public := false
	matched := false
	for _, route := range cfg.Routes {
		if !matchesUsername([]string(route.Match.Username), username) {
			continue
		}
		matched = true
		if route.Match.Role == "" {
			public = true
			break
		}
	}
	if public {
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
	if !matched {
		return callbacks, false
	}
	return callbacks, false
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
		if !matchesUsername([]string(route.Match.Username), username) {
			continue
		}
		if route.Match.Role != "" && slices.Contains(passwordRoles, route.Match.Role) {
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
		if matchesRouteAuth(route, username, roles) {
			return true
		}
	}
	return false
}

// muxMiddleware returns a wish.Middleware that routes each session based on
// the config's routes list.
func muxMiddleware(cfg *Config) wish.Middleware {
	return func(_ ssh.Handler) ssh.Handler {
		return func(s ssh.Session) {
			username := s.User()
			roles := G(s.Context())

			route := findRoute(cfg, username, roles, s.RawCommand())
			if route != nil {
				if route.Proxy.Host != "" {
					if err := proxySession(s, *route); err != nil {
						log.Error("Proxy error", "addr", route.Proxy.Host, "error", err)
						_, _ = fmt.Fprintf(s.Stderr(), "proxy error: %v\r\n", err)
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

func findRoute(cfg *Config, username string, roles []string, rawCommand string) *RouteEntry {
	for i := range cfg.Routes {
		if matchesRouteSession(cfg.Routes[i], username, roles, rawCommand) {
			return &cfg.Routes[i]
		}
	}
	return nil
}

func matchesRouteAuth(route RouteEntry, username string, roles []string) bool {
	if !matchesUsername([]string(route.Match.Username), username) {
		return false
	}
	if route.Match.Role != "" && !slices.Contains(roles, route.Match.Role) {
		return false
	}
	return true
}

func matchesRouteSession(route RouteEntry, username string, roles []string, rawCommand string) bool {
	if !matchesRouteAuth(route, username, roles) {
		return false
	}
	if route.Match.Cmd != "" {
		matched, err := regexp.MatchString(route.Match.Cmd, rawCommand)
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func matchesUsername(patterns []string, username string) bool {
	for _, pattern := range patterns {
		matched, err := path.Match(pattern, username)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// runCmd executes the configured command for the session.
func runCmd(s ssh.Session, command string, withPTY bool) error {
	cmd := exec.CommandContext(s.Context(), "sh", "-c", command)
	cmd.Env = append(os.Environ(), s.Environ()...)

	if withPTY {
		ptyReq, _, ok := s.Pty()
		if !ok {
			return fmt.Errorf("pty requested but client did not allocate one")
		}
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
		// Give the child process ownership of the PTY so full-screen apps receive
		// terminal resize signals and behave like they were launched by sshd.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid:  true,
			Setctty: true,
			Ctty:    0,
		}
		if err := ptyReq.Start(cmd); err != nil {
			return fmt.Errorf("start pty cmd: %w", err)
		}
		return cmd.Wait()
	}

	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cmd: %w", err)
	}
	return cmd.Wait()
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

package server

import (
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/charmbracelet/ssh"
	htpasswd "github.com/tg123/go-htpasswd"
	gossh "golang.org/x/crypto/ssh"

	"sshmux/internal/config"
)

func WithAuth(cfg *config.Config) ssh.Option {
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

func authCallbacks(ctx ssh.Context, cfg *config.Config, username string) (gossh.ServerAuthCallbacks, bool) {
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

func usernameMatchingRoutes(cfg *config.Config, username string) []config.RouteEntry {
	var routes []config.RouteEntry
	for _, route := range cfg.Routes {
		if route.Username.Match(username) {
			routes = append(routes, route)
		}
	}
	return routes
}

func routesArePublic(routes []config.RouteEntry) bool {
	for _, route := range routes {
		if route.Role != "" {
			return false
		}
	}
	return true
}

func publicKeyRoles(cfg *config.Config, key ssh.PublicKey) []string {
	fp := gossh.FingerprintSHA256(key)
	var roles []string
	for _, auth := range cfg.Auth {
		if auth.Fingerprint != "" && auth.Fingerprint == fp {
			roles = append(roles, auth.Role...)
			continue
		}
		if auth.Key.Fingerprint != "" && auth.Key.Fingerprint == fp {
			roles = append(roles, auth.Role...)
			continue
		}
		if auth.Key.PublicKey != nil && ssh.KeysEqual(key, auth.Key.PublicKey) {
			roles = append(roles, auth.Role...)
		}
	}
	return roles
}

func passwordRoles(cfg *config.Config, password string) []string {
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

func passwordAllowedForUsername(cfg *config.Config, username string) bool {
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

func passwordAuthRoles(cfg *config.Config) []string {
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

func canReachRoute(cfg *config.Config, username string, roles []string) bool {
	for _, route := range cfg.Routes {
		if route.Username.Match(username) && routeRoleAllowed(route, roles) {
			return true
		}
	}
	return false
}

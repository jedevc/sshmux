package server

import (
	"fmt"
	"slices"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"github.com/charmbracelet/ssh"

	"sshmux/internal/cloud"
	"sshmux/internal/config"
)

// MuxMiddleware returns a wish.Middleware that routes each session based on
// the config's routes list.
func MuxMiddleware(cfg *config.Config, providerSets ...cloud.Providers) wish.Middleware {
	providers := cloud.Providers(nil)
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
						_ = s.Exit(ExitCode(err))
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
						_ = s.Exit(ExitCode(err))
					}
					return
				}
				if route.Run.Cmd != "" {
					if err := runCmd(s, route.Run.Cmd, route.Run.Pty); err != nil {
						log.Error("Command error", "cmd", route.Run.Cmd, "error", err)
						_ = s.Exit(ExitCode(err))
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

func findRoute(cfg *config.Config, username string, _ []string) *config.RouteEntry {
	route, _ := findRouteIndex(cfg, username, nil)
	return route
}

func findRouteIndex(cfg *config.Config, username string, _ []string) (*config.RouteEntry, int) {
	for i := range cfg.Routes {
		if matchesRouteSession(cfg.Routes[i], username) {
			return &cfg.Routes[i], i
		}
	}
	return nil, -1
}

func routeRoleAllowed(route config.RouteEntry, roles []string) bool {
	return route.Role == "" || slices.Contains(roles, route.Role)
}

func matchesRouteSession(route config.RouteEntry, username string) bool {
	return route.Username.Match(username)
}

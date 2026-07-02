package cloud

import (
	"context"
	"fmt"

	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshmux/internal/config"
)

type Provider interface {
	Dial(ctx context.Context, s ssh.Session) (*gossh.Client, func(), error)
}

type Providers map[int]Provider

func BuildProviders(cfg *config.Config) (Providers, error) {
	providers := make(Providers)
	for i, route := range cfg.Routes {
		if route.Cloud.Provider == "" {
			continue
		}
		switch route.Cloud.Provider {
		case "unikraft":
			provider, err := NewUnikraftProvider(route.Cloud)
			if err != nil {
				return nil, fmt.Errorf("route %d unikraft provider: %w", i, err)
			}
			providers[i] = provider
		default:
			return nil, fmt.Errorf("route %d cloud provider %q is not supported", i, route.Cloud.Provider)
		}
	}
	return providers, nil
}

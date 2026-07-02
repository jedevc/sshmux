package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Config is the top-level configuration structure.
type Config struct {
	Auth   []AuthEntry  `json:"auth"`
	Routes []RouteEntry `json:"routes"`
}

type AuthEntry struct {
	Fingerprint string        `json:"fingerprint"`
	Key         string        `json:"key"`
	Password    string        `json:"password"`
	Role        StringOrSlice `json:"role"`
}

// RouteEntry describes where/how to handle a matched session.
// Exactly one of Proxy, Run, or Cloud must be set.
type RouteEntry struct {
	Username Pattern `json:"username"`
	Role     string  `json:"role"`

	Run   RunEntry   `json:"run"`
	Proxy ProxyEntry `json:"proxy"`
	Cloud CloudEntry `json:"cloud"`
}

type RunEntry struct {
	Cmd string `json:"cmd"`
	Pty bool   `json:"pty"`
}

type ProxyEntry struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
	HostKey  string `json:"host_key"`
}

type CloudEntry struct {
	Provider   string   `json:"provider"`
	Image      string   `json:"image"`
	Metro      string   `json:"metro"`
	MemoryMB   int64    `json:"memory_mb"`
	SessionTTL Duration `json:"session_ttl"`
}

// Load reads and parses the YAML file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	for i, route := range c.Routes {
		targets := 0
		if route.Run.Cmd != "" {
			targets++
		}
		if route.Proxy.Host != "" {
			targets++
		}
		if route.Cloud.Provider != "" {
			targets++
		}
		if targets != 1 {
			return fmt.Errorf("route %d must set exactly one of run, proxy, or cloud", i)
		}
		if route.Cloud.Provider != "" && route.Cloud.Provider != "unikraft" {
			return fmt.Errorf("route %d cloud provider %q is not supported", i, route.Cloud.Provider)
		}
	}
	return nil
}

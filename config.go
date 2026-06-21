package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// StringOrSlice unmarshals either a YAML string or a YAML sequence of strings.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*s = []string{value.Value}
	case yaml.SequenceNode:
		var ss []string
		if err := value.Decode(&ss); err != nil {
			return err
		}
		*s = ss
	default:
		return fmt.Errorf("expected string or sequence, got %v", value.Kind)
	}
	return nil
}

// AuthEntry matches an authentication method to a set of roles.
type AuthEntry struct {
	// Fingerprint is a SHA256 public-key fingerprint, e.g. "SHA256:..."
	Fingerprint string `yaml:"fingerprint"`
	// Key is a raw authorized-keys-format public key.
	Key string `yaml:"key"`
	// Password is a plain-text password or an nginx-style password hash.
	Password string        `yaml:"password"`
	Role     StringOrSlice `yaml:"role"`
}

type ProxyEntry struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Key      string `yaml:"key"`
	HostKey  string `yaml:"host_key"`
}

// RouteEntry describes where/how to handle a matched session.
// Either Proxy or Cmd must be set.
type RouteEntry struct {
	// Username is a list of SSH usernames or shell-style patterns that trigger this route.
	Username StringOrSlice `yaml:"username"`
	// Role restricts the route to users that have been granted this role.
	Role string `yaml:"role"`
	// Proxy forwards the session to another SSH server.
	Proxy ProxyEntry `yaml:"proxy"`
	// Cmd is a shell command to execute for the session.
	Cmd string `yaml:"cmd"`
	// Pty runs Cmd inside a real PTY. Use this for full-screen terminal apps.
	Pty bool `yaml:"pty"`
}

// Config is the top-level configuration structure.
type Config struct {
	Auth   []AuthEntry  `yaml:"auth"`
	Routes []RouteEntry `yaml:"routes"`
}

// LoadConfig reads and parses the YAML file at path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

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

type Pattern struct {
	AllowRegexp []*regexp.Regexp
	DenyRegexp  []*regexp.Regexp
	Allow       []string
	Deny        []string
}

func (p *Pattern) UnmarshalYAML(value *yaml.Node) error {
	var parts StringOrSlice
	if err := parts.UnmarshalYAML(value); err != nil {
		return err
	}
	parsed, err := parsePattern([]string(parts))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

func parsePattern(parts []string) (Pattern, error) {
	var pattern Pattern
	for _, part := range parts {
		deny := strings.HasPrefix(part, "!")
		if deny {
			part = strings.TrimPrefix(part, "!")
		}
		if strings.HasPrefix(part, "/") && strings.HasSuffix(part, "/") && len(part) >= 2 {
			re, err := regexp.Compile(strings.TrimSuffix(strings.TrimPrefix(part, "/"), "/"))
			if err != nil {
				return Pattern{}, fmt.Errorf("compile pattern %q: %w", part, err)
			}
			if deny {
				pattern.DenyRegexp = append(pattern.DenyRegexp, re)
			} else {
				pattern.AllowRegexp = append(pattern.AllowRegexp, re)
			}
			continue
		}
		if deny {
			pattern.Deny = append(pattern.Deny, part)
		} else {
			pattern.Allow = append(pattern.Allow, part)
		}
	}
	return pattern, nil
}

func (p Pattern) Match(value string) bool {
	for _, deny := range p.Deny {
		if matchGlob(deny, value) {
			return false
		}
	}
	for _, deny := range p.DenyRegexp {
		if deny.MatchString(value) {
			return false
		}
	}
	hasAllow := len(p.Allow) > 0 || len(p.AllowRegexp) > 0
	for _, allow := range p.Allow {
		if matchGlob(allow, value) {
			return true
		}
	}
	for _, allow := range p.AllowRegexp {
		if allow.MatchString(value) {
			return true
		}
	}
	return !hasAllow
}

func matchGlob(pattern string, value string) bool {
	matched, err := path.Match(pattern, value)
	return err == nil && matched
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

type MatchEntry struct {
	Username Pattern `yaml:"username"`
	Role     string  `yaml:"role"`
	Cmd      string  `yaml:"cmd"`
}

type RunEntry struct {
	Cmd string `yaml:"cmd"`
	Pty bool   `yaml:"pty"`
}

// RouteEntry describes where/how to handle a matched session.
// Either Proxy or Run must be set.
type RouteEntry struct {
	Match MatchEntry `yaml:"match"`
	Run   RunEntry   `yaml:"run"`
	// Proxy forwards the session to another SSH server.
	Proxy ProxyEntry `yaml:"proxy"`
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

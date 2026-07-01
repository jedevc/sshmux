package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// StringOrSlice unmarshals either a YAML string or a YAML sequence of strings.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*s = multiple
		return nil
	}
	return fmt.Errorf("expected string or sequence")
}

type Pattern struct {
	AllowRegexp []*regexp.Regexp
	DenyRegexp  []*regexp.Regexp
	Allow       []string
	Deny        []string
}

func (p *Pattern) UnmarshalJSON(data []byte) error {
	var parts StringOrSlice
	if err := parts.UnmarshalJSON(data); err != nil {
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
	Fingerprint string `json:"fingerprint"`
	// Key is a raw authorized-keys-format public key.
	Key string `json:"key"`
	// Password is a plain-text password or an nginx-style password hash.
	Password string        `json:"password"`
	Role     StringOrSlice `json:"role"`
}

type ProxyEntry struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
	HostKey  string `json:"host_key"`
}

type RunEntry struct {
	Cmd string `json:"cmd"`
	Pty bool   `json:"pty"`
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("expected duration string")
	}
	if value == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

type CloudEntry struct {
	Provider   string   `json:"provider"`
	Image      string   `json:"image"`
	Metro      string   `json:"metro"`
	MemoryMB   int64    `json:"memory_mb"`
	SessionTTL Duration `json:"session_ttl"`
}

// RouteEntry describes where/how to handle a matched session.
// Exactly one of Proxy, Run, or Cloud must be set.
type RouteEntry struct {
	Username Pattern  `json:"username"`
	Role     string   `json:"role"`
	Run      RunEntry `json:"run"`
	// Proxy forwards the session to another SSH server.
	Proxy ProxyEntry `json:"proxy"`
	// Cloud provisions a provider-backed SSH runtime for the session.
	Cloud CloudEntry `json:"cloud"`
}

// Config is the top-level configuration structure.
type Config struct {
	Auth   []AuthEntry  `json:"auth"`
	Routes []RouteEntry `json:"routes"`
}

// LoadConfig reads and parses the YAML file at path.
func LoadConfig(path string) (*Config, error) {
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

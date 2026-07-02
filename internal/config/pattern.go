package config

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

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
	parsed, err := ParsePattern([]string(parts))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

func ParsePattern(parts []string) (Pattern, error) {
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

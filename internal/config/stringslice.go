package config

import (
	"encoding/json"
	"fmt"
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

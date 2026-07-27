// Package dnfconfig validates the INI syntax consumed by dnf-automatic and DNF5 automatic.
package dnfconfig

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// ParseStrict returns lower-cased section/key names and values. Ambiguous input is rejected so a
// duplicate policy cannot look healthy to SUN while the package manager refuses to run it.
func ParseStrict(data []byte) (map[string]string, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("DNF automatic configuration contains NUL data")
	}
	values := make(map[string]string)
	sections := make(map[string]bool)
	section := ""
	for number, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if len(trimmed) < 3 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
				return nil, fmt.Errorf("invalid DNF INI section on line %d", number+1)
			}
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			if section == "" {
				return nil, fmt.Errorf("empty DNF INI section on line %d", number+1)
			}
			if sections[section] {
				return nil, fmt.Errorf("duplicate DNF INI section %q", section)
			}
			sections[section] = true
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("DNF INI setting appears before a section on line %d", number+1)
		}
		key, value, ok := strings.Cut(trimmed, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid DNF INI setting on line %d", number+1)
		}
		qualified := section + "." + key
		if _, duplicate := values[qualified]; duplicate {
			return nil, fmt.Errorf("duplicate DNF INI setting %q", qualified)
		}
		values[qualified] = strings.ToLower(strings.TrimSpace(value))
	}
	return values, nil
}

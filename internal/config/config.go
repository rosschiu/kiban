// SPDX-License-Identifier: Apache-2.0

// Package config loads configuration from environment variables, with
// support for *_FILE secret-file variants that take precedence over the
// plain env var when both are set.
package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Field describes one configuration value to load.
type Field struct {
	Name     string // environment variable name, e.g. "DATABASE_URL"
	Required bool
	Default  string
}

// Spec is the set of fields to load.
type Spec []Field

// MissingError is returned when one or more required fields have no value.
// It lists every missing field name, not just the first.
type MissingError struct {
	Names []string
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("config: missing required values: %s", strings.Join(e.Names, ", "))
}

// Load reads the given spec from the environment. For each field, the
// <NAME>_FILE variant (if set) wins over the plain <NAME> env var: its
// content is read from disk and used as the value. If neither is set, the
// field's Default is used. A required field with no value from either
// source (and no default) is an error; all missing names are collected and
// reported together, not just the first.
func Load(spec Spec) (map[string]string, error) {
	values := make(map[string]string, len(spec))
	var missing []string

	for _, f := range spec {
		fileName := f.Name + "_FILE"
		if filePath, ok := os.LookupEnv(fileName); ok && filePath != "" {
			content, err := os.ReadFile(filePath)
			if err != nil {
				// Set but unreadable is a deployment error for optional and required fields
				// alike — never silently an empty value, never reported as "missing".
				return nil, fmt.Errorf("config: %s is set but unreadable: %w", fileName, err)
			}
			values[f.Name] = strings.TrimSpace(string(content))
			continue
		}

		if v, ok := os.LookupEnv(f.Name); ok {
			values[f.Name] = v
			continue
		}

		if f.Default != "" {
			values[f.Name] = f.Default
			continue
		}

		if f.Required {
			missing = append(missing, f.Name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, &MissingError{Names: missing}
	}

	return values, nil
}

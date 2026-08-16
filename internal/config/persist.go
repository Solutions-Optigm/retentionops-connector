package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Persist writes a configuration back to its file.
//
// Through a temporary file in the same directory and an atomic rename, so a connector that is
// interrupted mid-write never finds a half-written configuration on restart — which is the one
// failure that would leave a host unable to start at all.
//
// The mode matches what `install` lays down: readable by the connector's group, never by the
// world. A configuration names hosts and role names, and those are the customer's business.
func Persist(path string, configuration *Config) error {
	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("config: encode %s: %w", path, err)
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(temporary, encoded, 0o640); err != nil {
		return fmt.Errorf("config: write %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("config: install %s: %w", path, err)
	}
	return nil
}

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Persist writes a configuration back to its file, durably.
//
// Temporary file, fsync, atomic rename, then fsync of the directory. The last step is the one
// usually forgotten and the one that matters after a power loss: a rename is atomic with respect
// to readers, but the directory entry itself is not on disk until the directory is synced. Without
// it a host can come back up with neither the old file nor the new one.
//
// The mode matches what `install` lays down: readable by the connector's group, never by the
// world. A configuration names hosts and role names, and those are the customer's business.
func Persist(path string, configuration *Config) error {
	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("config: encode %s: %w", path, err)
	}
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, "."+filepath.Base(path)+".tmp")

	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640) //nolint:gosec // fixed private mode
	if err != nil {
		return fmt.Errorf("config: write %s: %w", temporary, err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("config: write %s: %w", temporary, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("config: sync %s: %w", temporary, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("config: close %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("config: install %s: %w", path, err)
	}
	if handle, err := os.Open(directory); err == nil { //nolint:gosec // the configuration's own directory
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

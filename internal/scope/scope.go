// Package scope records which schemas a connector may enter, on the host that owns that decision.
//
// `allowed_schemas` is the local safety boundary. The control plane may not read it and may not
// widen it (rule 8, I32), which is why it is chosen here from what PostgreSQL actually grants the
// reader identity rather than typed from memory into a prompt — and why the list of names never
// leaves this machine.
//
// Nothing here can make a deletion possible. Allowing a schema makes it visible to discovery and
// planning; deleting still needs a table rule, execution mode and an approval, and those come from
// the separate, reviewed enablement flow.
package scope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"gopkg.in/yaml.v3"
)

// ErrOutsideGrants is returned for a schema PostgreSQL does not let the reader enter.
//
// Refused rather than written: an allow-list entry the database will block anyway is a promise
// the connector cannot keep, and the empty discovery that follows looks like a product fault.
var ErrOutsideGrants = errors.New("scope: the reader identity has no access to this schema")

// Set replaces the allowed schemas of one source and rewrites the configuration file.
//
// The previous file is kept beside the new one. This is the operator's document — the connector
// writes it only because they asked it to, from a command they ran, and a backup is what makes
// that reversible without a copy they had to remember to take.
func Set(path string, configuration *config.Config, sourceID string, chosen, reachable []string) (string, error) {
	source, known := configuration.Source(sourceID)
	if !known || source == nil {
		return "", fmt.Errorf("scope: source %s is not declared in this connector's configuration", sourceID)
	}
	if source.Pending() {
		return "", errors.New("scope: this source has no configuration yet; send it from the console first")
	}
	if len(chosen) == 0 {
		return "", errors.New("scope: choose at least one schema, or this connector can reach nothing")
	}
	for _, name := range chosen {
		if !slices.Contains(reachable, name) {
			return "", fmt.Errorf("%w: %s", ErrOutsideGrants, name)
		}
	}

	previous := append([]string(nil), source.Safety.AllowedSchemas...)
	slices.Sort(chosen)
	source.Safety.AllowedSchemas = slices.Compact(chosen)
	if err := configuration.Validate(); err != nil {
		source.Safety.AllowedSchemas = previous
		return "", fmt.Errorf("scope: the resulting configuration is not usable: %w", err)
	}

	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		return "", fmt.Errorf("scope: render %s: %w", path, err)
	}
	backup, err := keepPrevious(path)
	if err != nil {
		return "", err
	}
	if err := write(path, encoded); err != nil {
		return "", err
	}
	return backup, nil
}

// keepPrevious copies the current file beside itself before it is replaced.
func keepPrevious(path string) (string, error) {
	current, err := os.ReadFile(path) //nolint:gosec // the operator's own configuration
	if err != nil {
		return "", fmt.Errorf("scope: read %s: %w", path, err)
	}
	backup := path + ".backup-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(backup, current, 0o640); err != nil {
		return "", fmt.Errorf("scope: back up %s: %w", path, err)
	}
	return backup, nil
}

// write replaces the configuration atomically, so a crash cannot leave a connector with half a
// safety policy — the one file where a truncated read would silently narrow or widen what is
// reachable.
func write(path string, content []byte) error {
	directory := filepath.Dir(path)
	staged, err := os.CreateTemp(directory, ".retentionops-config-*")
	if err != nil {
		return fmt.Errorf("scope: stage %s: %w", path, err)
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)

	if err := staged.Chmod(0o640); err != nil {
		_ = staged.Close()
		return err
	}
	if _, err := staged.Write(content); err != nil {
		_ = staged.Close()
		return fmt.Errorf("scope: write %s: %w", path, err)
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return fmt.Errorf("scope: install %s: %w", path, err)
	}
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("scope: open %s: %w", directory, err)
	}
	defer handle.Close()
	return handle.Sync()
}

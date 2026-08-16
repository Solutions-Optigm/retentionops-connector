package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ManagedFileName is where configuration received from RetentionOps is persisted.
//
// Deliberately not beside `connector.yaml`. That file belongs to the operator: they wrote it, they
// review it, and a product that silently rewrote it would be editing a document its owner believes
// they control. What arrives over the wire lands here instead, under the connector's own state
// root, and the two are merged at load.
const ManagedFileName = "source-config.yaml"

// ManagedSource is the whole of what a RetentionOps envelope may set on a source.
//
// A closed struct rather than a YAML merge, so the allow-list is a property of the type. A generic
// overlay would make a source-configuration envelope into a remote administration channel for the
// connector: the fields that are absent here are absent on purpose, and adding one is a protocol
// change with a review rather than a line somebody widens.
//
// Absent, and staying absent: `control_plane` (which would let the control plane redirect a
// connector at itself), `identity` and `state` paths, `telemetry`, `mode`, `safety` — the local
// policy that decides what may be deleted (I32, rule 8) — and every `SecretRef`, which names a
// file on this host that no envelope carries a value for.
type ManagedSource struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Database     string `yaml:"database"`
	ReaderRole   string `yaml:"reader_role"`
	ExecutorRole string `yaml:"executor_role,omitempty"`
	TLSMode      string `yaml:"tls_mode"`
}

// ManagedOverlay is the persisted form: one entry per source the console has configured.
type ManagedOverlay struct {
	Version int                       `yaml:"version"`
	Sources map[string]*ManagedSource `yaml:"sources"`
}

// ManagedOverlayVersion is the only shape this connector reads back.
const ManagedOverlayVersion = 1

// LoadManagedOverlay reads the overlay, treating absence as an empty one.
//
// A connector that has never been configured from the console is the normal case, not an error.
// Unknown fields are refused for the same reason the base configuration refuses them: a typo that
// is silently ignored leaves an operator believing a setting is in force when it is not.
func LoadManagedOverlay(path string) (*ManagedOverlay, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-known state path
	if err != nil {
		if os.IsNotExist(err) {
			return &ManagedOverlay{Version: ManagedOverlayVersion, Sources: map[string]*ManagedSource{}}, nil
		}
		return nil, fmt.Errorf("config: read managed overlay %s: %w", path, err)
	}
	overlay := &ManagedOverlay{}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(overlay); err != nil {
		return nil, fmt.Errorf("config: parse managed overlay %s: %w", path, err)
	}
	if overlay.Version != ManagedOverlayVersion {
		return nil, fmt.Errorf("config: managed overlay version %d is not supported", overlay.Version)
	}
	if overlay.Sources == nil {
		overlay.Sources = map[string]*ManagedSource{}
	}
	return overlay, nil
}

// ErrManagedUnknownSource is returned for an overlay entry naming a source the base does not declare.
//
// The operator's file is the authority on which sources exist. An overlay that could introduce one
// would let the control plane add a target to a host by asserting it.
var ErrManagedUnknownSource = errors.New("config: managed overlay names a source the local configuration does not declare")

// ApplyManagedOverlay merges the overlay into a base configuration, in place.
//
// Called on the loaded base before validation, so the effective configuration is always
// base → overlay → validate. An entry for an unknown source is refused rather than ignored: a
// silently dropped overlay is a console reporting success over a connector that changed nothing.
func ApplyManagedOverlay(base *Config, overlay *ManagedOverlay) error {
	for id, managed := range overlay.Sources {
		source, known := base.Sources[id]
		if !known || source == nil {
			return fmt.Errorf("%w: %s", ErrManagedUnknownSource, id)
		}
		if managed == nil {
			continue
		}
		source.Host = managed.Host
		source.Port = managed.Port
		source.Database = managed.Database
		source.TLS.Mode = managed.TLSMode
		source.Reader.Username = managed.ReaderRole
		if managed.ExecutorRole != "" {
			source.Executor.Username = managed.ExecutorRole
		}
	}
	return nil
}

// PersistManagedOverlay writes the overlay with the same durability the base file gets.
//
// Temporary file, fsync, atomic rename, fsync of the directory. The last is the one usually
// forgotten and the one that matters after a power loss: a rename is atomic for readers, but the
// directory entry is not on disk until the directory is synced.
//
// Mode 0600: this file is the connector's own, and nothing but the connector reads it.
func PersistManagedOverlay(path string, overlay *ManagedOverlay) error {
	encoded, err := yaml.Marshal(overlay)
	if err != nil {
		return fmt.Errorf("config: encode managed overlay: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("config: create %s: %w", directory, err)
	}
	temporary := filepath.Join(directory, "."+filepath.Base(path)+".tmp")

	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // fixed private mode
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
	if handle, err := os.Open(directory); err == nil { //nolint:gosec // the overlay's own directory
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

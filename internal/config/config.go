// Package config loads the one file that decides what this connector can reach.
//
// Everything here is customer-owned. The control plane has no endpoint that reads this file, no
// endpoint that writes it, and no way to learn what is in it beyond the counts a heartbeat
// carries. Reloading it is a local action — a signal or a restart — never a remote one.
package config

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
	"gopkg.in/yaml.v3"
)

// TLS modes accepted for a target database.
const (
	TLSVerifyFull = "verify-full"
	TLSVerifyCA   = "verify-ca"
	TLSRequire    = "require"

	// SourceModeDiscoveryOnly keeps the connector useful for connection tests and schema
	// discovery without configuring any destructive identity. SourceModeExecution is a local,
	// customer-owned opt-in and is never writable by the control plane.
	SourceModeDiscoveryOnly = "discovery_only"
	SourceModeExecution     = "execution"
	ExecutionDisabledCode   = "EXECUTION_DISABLED"

	// ConfiguredByLocal is the default and the stricter one: this file describes the database,
	// and every field must be present and valid before the connector will start.
	ConfiguredByLocal = "local"
	// ConfiguredByRetentionOps means the console sends where to connect, sealed to this
	// connector (ADR-034). Never what may be deleted.
	ConfiguredByRetentionOps = "retentionops"
)

// SecretRef names where a credential lives. It is a reference, never a value: a password
// literal has no representation in this file format, so a leaked configuration leaks the shape
// of the deployment and nothing else.
type SecretRef struct {
	Provider string `yaml:"provider"`
	Ref      string `yaml:"ref"`
}

// Credential is one PostgreSQL identity the connector may assume.
type Credential struct {
	Username string    `yaml:"username"`
	Password SecretRef `yaml:"password"`
}

// TLS is how the connector authenticates the target database.
type TLS struct {
	Mode   string `yaml:"mode"`
	CAFile string `yaml:"ca_file"`
}

// Source is one target database: where it is, which two identities may be assumed against it,
// and what the local safety policy permits there.
//
// Reader and Executor are separate on purpose and separated again at runtime: a planning job
// never causes the executor secret to be resolved. A flaw in the planning path therefore cannot
// hand an attacker the destructive identity, because that identity was never fetched.
type Source struct {
	Type string `yaml:"type"`
	Mode string `yaml:"mode,omitempty"`
	// ConfiguredBy says who describes this database: this file, or the RetentionOps console
	// through a sealed configuration.
	//
	// Written by `init` and read by an operator, which is the point of it being here rather than
	// inferred from an empty host. "Where is this database?" and "why is this field blank?" are
	// different questions, and a typo that emptied a host must keep failing loudly instead of
	// becoming a source that quietly waits for someone to configure it remotely.
	//
	// It never widens anything: the console may set where to connect and as whom, and the safety
	// policy below stays local and unreadable to it in both cases.
	ConfiguredBy string        `yaml:"configured_by,omitempty"`
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Database     string        `yaml:"database"`
	TLS          TLS           `yaml:"tls"`
	Reader       Credential    `yaml:"reader"`
	Executor     Credential    `yaml:"executor"`
	Safety       policy.Safety `yaml:"safety"`
}

// Pending reports a source RetentionOps configures that has not been configured yet.
//
// Declared, visible, and unusable. The alternative — refusing the file until a host is known —
// forces the operator to answer in a terminal every question the console is about to ask, and
// then to watch the console overwrite their answers. What this state buys is an order that makes
// sense: enrol, configure from the console, then test.
func (s *Source) Pending() bool {
	return s.ConfiguredBy == ConfiguredByRetentionOps && (s.Host == "" || s.Database == "")
}

// ControlPlane is where to reach RetentionOps. The connector only ever dials out.
type ControlPlane struct {
	URL string `yaml:"url"`
	//: How long the control plane may hold a poll open before answering "nothing to do". Long
	//: polling keeps latency low without a persistent connection and without an inbound port.
	PollWaitSeconds int `yaml:"poll_wait_seconds"`
	//: Seconds between heartbeats when idle.
	HeartbeatSeconds int `yaml:"heartbeat_seconds"`
	//: Optional PEM bundle for environments behind a TLS-inspecting proxy. Absent means the
	//: system trust store, which is the right default.
	CAFile string `yaml:"ca_file"`
}

// Telemetry is local-only observability. Nothing here is shipped to RetentionOps.
type Telemetry struct {
	//: Prometheus listener. Bind to a loopback or a private address; the connector never needs
	//: to be reachable from outside the customer's network.
	MetricsAddress string `yaml:"metrics_address"`
	LogFormat      string `yaml:"log_format"`
	LogLevel       string `yaml:"log_level"`
}

// Storage is a directory the connector owns.
type Storage struct {
	Directory string `yaml:"directory"`
}

// Config is the whole file.
type Config struct {
	ControlPlane ControlPlane       `yaml:"control_plane"`
	Identity     Storage            `yaml:"identity"`
	State        Storage            `yaml:"state"`
	Telemetry    Telemetry          `yaml:"telemetry"`
	Sources      map[string]*Source `yaml:"sources"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Load reads and validates a configuration file.
//
// Unknown fields are an error. A typo in a limit or an allow-list key would otherwise be silently
// ignored and leave the operator believing a control is in force that is not — which is worse
// than having no control at all.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is an operator-supplied argument
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	config.applyDefaults()

	// base → managed overlay → validate. The operator's file is never rewritten; what RetentionOps
	// configured lives beside the connector's state and is merged here, so both deployment shapes
	// -- a package on a host and an immutable container image -- behave identically.
	overlay, err := LoadManagedOverlay(ManagedOverlayPath(config.State.Directory))
	if err != nil {
		return nil, err
	}
	if err := ApplyManagedOverlay(&config, overlay); err != nil {
		return nil, err
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s is not usable: %w", path, err)
	}
	return &config, nil
}

// ManagedOverlayPath is where the connector persists what RetentionOps configured.
func ManagedOverlayPath(state string) string {
	return filepath.Join(ManagedDirectory(state), ManagedFileName)
}

func (c *Config) applyDefaults() {
	if c.ControlPlane.PollWaitSeconds == 0 {
		c.ControlPlane.PollWaitSeconds = 30
	}
	if c.ControlPlane.HeartbeatSeconds == 0 {
		c.ControlPlane.HeartbeatSeconds = 30
	}
	if c.Telemetry.LogFormat == "" {
		c.Telemetry.LogFormat = "json"
	}
	if c.Telemetry.LogLevel == "" {
		c.Telemetry.LogLevel = "info"
	}
	for _, source := range c.Sources {
		if source.Port == 0 {
			source.Port = 5432
		}
		if source.TLS.Mode == "" {
			// The safe default is the strict one. An operator who needs to relax it has to say
			// so, in writing, in a file their own security review can read.
			source.TLS.Mode = TLSVerifyFull
		}
		if source.Mode == "" {
			// Existing configurations predate the explicit mode. Inferring it from the local
			// allow-list preserves their behaviour without ever widening a non-destructive file.
			if source.Safety.GrantsDelete() {
				source.Mode = SourceModeExecution
			} else {
				source.Mode = SourceModeDiscoveryOnly
			}
		}
		if source.Safety.Drift.Mode == "" {
			source.Safety.Drift = policy.DriftPolicy{
				Mode:                "bounded",
				ExactMatchBelowRows: 1000,
				MaxRows:             100,
				MaxBasisPoints:      50,
			}
		}
	}
}

// Validate refuses a configuration the connector would have to interpret.
func (c *Config) Validate() error {
	if err := c.validateControlPlane(); err != nil {
		return err
	}
	if c.Identity.Directory == "" {
		return fmt.Errorf("identity.directory is required: it is where the private key lives")
	}
	if c.State.Directory == "" {
		return fmt.Errorf("state.directory is required: it is where the replay ledger lives")
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("no source is configured; the connector would have nothing to do")
	}
	for id, source := range c.Sources {
		if !uuidPattern.MatchString(id) {
			return fmt.Errorf("source key %q is not the lowercase UUID the console issued", id)
		}
		if err := source.validate(id); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateControlPlane() error {
	parsed, err := url.Parse(c.ControlPlane.URL)
	if err != nil {
		return fmt.Errorf("control_plane.url is not a URL: %w", err)
	}
	// Refusing plaintext here rather than "warning" about it: a connector that will talk to a
	// control plane over http is a connector whose job signatures can be stripped in transit by
	// anyone on the path, and no amount of local policy makes that acceptable.
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("control_plane.url must be an https URL")
	}
	if c.ControlPlane.PollWaitSeconds < 1 || c.ControlPlane.PollWaitSeconds > 300 {
		return fmt.Errorf("control_plane.poll_wait_seconds must be between 1 and 300")
	}
	if c.ControlPlane.HeartbeatSeconds < 5 || c.ControlPlane.HeartbeatSeconds > 3600 {
		return fmt.Errorf("control_plane.heartbeat_seconds must be between 5 and 3600")
	}
	return nil
}

func (s *Source) validate(id string) error {
	if s.Type != "postgresql" {
		return fmt.Errorf("source %s: only postgresql is implemented, not %q", id, s.Type)
	}
	switch s.ConfiguredBy {
	case "", ConfiguredByLocal, ConfiguredByRetentionOps:
	default:
		return fmt.Errorf("source %s: configured_by %q is not one of local, retentionops", id, s.ConfiguredBy)
	}
	if s.Pending() {
		return s.validatePending(id)
	}
	if s.Host == "" || s.Database == "" {
		return fmt.Errorf("source %s: host and database are required", id)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("source %s: port %d is out of range", id, s.Port)
	}
	switch s.Mode {
	case SourceModeDiscoveryOnly:
		if s.Safety.GrantsDelete() {
			return fmt.Errorf("source %s: mode discovery_only cannot grant delete", id)
		}
	case SourceModeExecution:
		if !s.Safety.GrantsDelete() {
			return fmt.Errorf("source %s: mode execution needs at least one table granting delete", id)
		}
	default:
		return fmt.Errorf("source %s: mode %q is not one of discovery_only, execution", id, s.Mode)
	}
	switch s.TLS.Mode {
	case TLSVerifyFull, TLSVerifyCA, TLSRequire:
	default:
		return fmt.Errorf("source %s: tls.mode %q is not one of verify-full, verify-ca, require", id, s.TLS.Mode)
	}
	// An absent ca_file is the host's own trust store, which is how every other TLS client on
	// this machine verifies a publicly trusted certificate. Refusing it used to force an operator
	// to name a path for a database that needed none, and the usual way out of that question was
	// to point at the public bundle and hope — or to drop to `require`, which verifies nothing.
	// Verification still happens in both cases; only the source of the roots differs.
	if err := s.Reader.validate(id, "reader"); err != nil {
		return err
	}
	if s.Executor.Username != "" || s.Executor.Password.Provider != "" || s.Executor.Password.Ref != "" {
		if err := s.Executor.validate(id, "executor"); err != nil {
			return err
		}
		if s.Executor.Username == s.Reader.Username {
			return fmt.Errorf("source %s: reader and executor are the same role, which erases the separation the two-identity design exists for", id)
		}
	} else if s.Safety.GrantsDelete() {
		return fmt.Errorf("source %s: executor is required because the local policy grants delete", id)
	}
	if err := s.Safety.Validate(); err != nil {
		return fmt.Errorf("source %s: safety policy: %w", id, err)
	}
	return nil
}

// validatePending checks what a source can be held to before anybody has said where it is.
//
// Two things are still required and both are local: somewhere to read this source's password
// from, and a safety policy that grants no delete. The second is the one that matters — a source
// nobody has described yet must not be a source that could delete the moment a configuration
// arrives, because enabling execution is a separate, reviewed, local decision and the console has
// no part in it.
func (s *Source) validatePending(id string) error {
	if s.Safety.GrantsDelete() {
		return fmt.Errorf(
			"source %s: a source configured by retentionops cannot grant delete before it is configured; "+
				"enable execution locally once it is", id)
	}
	if s.Mode == SourceModeExecution {
		return fmt.Errorf("source %s: mode execution needs a configured database", id)
	}
	if s.Reader.Password.Provider == "" || s.Reader.Password.Ref == "" {
		return fmt.Errorf("source %s: reader.password needs a provider and a ref, which stay local", id)
	}
	// No allowed schema yet, and that is the safest state there is: this connector can reach
	// nothing. The choice is made once the database is configured and reachable, from the schemas
	// PostgreSQL actually grants the reader — `retentionops-connector source scope` — rather than
	// typed from memory before anybody knows what is in there.
	if len(s.Safety.AllowedSchemas) == 0 {
		return nil
	}
	if err := s.Safety.Validate(); err != nil {
		return fmt.Errorf("source %s: safety policy: %w", id, err)
	}
	return nil
}

func (c *Credential) validate(id, role string) error {
	if !protocolv1.IsIdentifier(c.Username) {
		return fmt.Errorf("source %s: %s.username %q is not a plain lowercase identifier", id, role, c.Username)
	}
	if c.Password.Provider == "" || c.Password.Ref == "" {
		return fmt.Errorf("source %s: %s.password needs a provider and a ref", id, role)
	}
	return nil
}

// PolicyDigest is the digest of every local safety policy in force, in the canonical form used
// throughout the protocol.
//
// It travels in the heartbeat so the console can show the customer which policy was active when
// a job ran. Nothing in the control plane can change it; a change in the console is always the
// visible consequence of someone editing a file on the customer's own host.
func (c *Config) PolicyDigest() (string, error) {
	policies := make(map[string]policy.Safety, len(c.Sources))
	for id, source := range c.Sources {
		policies[id] = source.Safety
	}
	return protocolv1.DigestOf(policies)
}

// Source returns the configuration for a data source id, or false if the customer never
// configured it. An unknown source is the first refusal in the job pipeline: the control plane
// can name any identifier it likes and reach nothing.
func (c *Config) Source(id string) (*Source, bool) {
	source, ok := c.Sources[id]
	return source, ok
}

// RequireDirectoryIsPrivate refuses to use a directory other users can read.
//
// The private key and the replay ledger live here. A world-readable identity directory would
// make key theft a matter of reading a file, so this is checked at startup rather than
// documented as a deployment note nobody reads.
func RequireDirectoryIsPrivate(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("config: %s: %w", directory, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("config: %s is not a directory", directory)
	}
	if mode := info.Mode().Perm(); mode&fs.FileMode(0o077) != 0 {
		return fmt.Errorf("config: %s is mode %#o; it must not be readable by group or other", directory, mode)
	}
	return nil
}

// NoncesDirectory is where the replay ledger lives inside the state directory.
func NoncesDirectory(state string) string { return filepath.Join(state, "nonces") }

// ManagedDirectory sits beside the state directory rather than inside it.
//
// `state` is what the connector accumulates while running -- ledgers, nonces, things nobody reads
// on purpose. `managed` is configuration that arrived from RetentionOps and that an operator will
// want to open and read. Naming them apart is what keeps "what did the console change" answerable
// without reading a replay ledger.
func ManagedDirectory(state string) string {
	return filepath.Join(filepath.Dir(strings.TrimRight(state, "/")), "managed")
}

// Describe renders a source for a log line. Host and database are the customer's own
// infrastructure names, which they already know; no credential, secret reference or row content
// can reach this string.
func (s *Source) Describe() string {
	return fmt.Sprintf("%s://%s:%d/%s", s.Type, s.Host, s.Port, s.Database)
}

// Redact keeps a secret reference printable without printing what it resolves to.
func (r SecretRef) Redact() string {
	if r.Provider == "" {
		return "(unset)"
	}
	return r.Provider + ":" + strings.Repeat("*", 8)
}

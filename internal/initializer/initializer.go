// Package initializer renders a reviewable connector installation without executing it.
//
// The generated directory is an operator-owned handoff: no SQL is applied, no service is
// installed, no enrollment is attempted and no configuration crosses the network.
package initializer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	"gopkg.in/yaml.v3"
)

const (
	// AnswersVersion is bumped whenever an answers file would otherwise change meaning.
	AnswersVersion  = 2
	BundleVersion   = 1
	PlatformSystemd = "systemd"
	PlatformCompose = "compose"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Runtime locations the generated artifacts agree on. The bundle is a staging directory; every
// command in NEXT-STEPS.txt points at the path the running connector will actually read.
const (
	identityDirectory = "/var/lib/retentionops/identity"
	stateDirectory    = "/var/lib/retentionops/state"
	runtimeConfigPath = "/etc/retentionops/connector.yaml"
	imageRepository   = "ghcr.io/solutions-optigm/retentionops-connector"
)

// Answers is the strict, versioned input shared by interactive and unattended initialization.
// Credential fields are SecretRef values, so there is deliberately nowhere to put a secret.
type Answers struct {
	Version         int          `yaml:"version"`
	Platform        string       `yaml:"platform"`
	OutputDirectory string       `yaml:"output_directory"`
	OrganizationID  string       `yaml:"organization_id"`
	SourceID        string       `yaml:"source_id"`
	ControlPlane    ControlPlane `yaml:"control_plane"`
	Source          Source       `yaml:"source"`
}

type ControlPlane struct {
	URL    string `yaml:"url"`
	CAFile string `yaml:"ca_file,omitempty"`
}

type Source struct {
	Host            string            `yaml:"host"`
	Port            int               `yaml:"port"`
	Database        string            `yaml:"database"`
	TLSCASourceFile string            `yaml:"tls_ca_source_file"`
	TLSCAFile       string            `yaml:"tls_ca_file,omitempty"`
	Reader          config.Credential `yaml:"reader"`
	// Executor remains accepted for v1 answers-file compatibility. New bundles deliberately
	// omit it until a local operator enables destructive execution.
	Executor       config.Credential `yaml:"executor,omitempty"`
	AllowedSchemas []string          `yaml:"allowed_schemas"`
}

// BundleManifest is the machine-readable handoff consumed by `install`. It contains deployment
// shape and file digests only; secrets have no representation in this document.
type BundleManifest struct {
	Version         int               `json:"version"`
	Platform        string            `json:"platform"`
	OrganizationID  string            `json:"organization_id,omitempty"`
	SourceID        string            `json:"source_id"`
	ControlPlaneURL string            `json:"control_plane_url"`
	RuntimeConfig   string            `json:"runtime_config"`
	PostgreSQL      BundlePostgreSQL  `json:"postgresql"`
	Artifacts       map[string]string `json:"artifacts"`
}

type BundlePostgreSQL struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Database      string `json:"database"`
	CASourceFile  string `json:"ca_source_file,omitempty"`
	CARuntimeFile string `json:"ca_runtime_file"`
}

// LoadAnswers rejects unknown fields and trailing documents. A misspelled safety input must
// fail visibly instead of being silently replaced by a default.
func LoadAnswers(path string) (Answers, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // explicitly supplied local operator file
	if err != nil {
		return Answers{}, fmt.Errorf("init: read answers file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var answers Answers
	if err := decoder.Decode(&answers); err != nil {
		return Answers{}, fmt.Errorf("init: parse answers file: %w", err)
	}
	if answers.Version == 1 {
		// v1 used tls_ca_file solely as a runtime path and generated executor placeholders. It
		// remains readable so an existing reviewed answers file can be upgraded in place.
		answers.Version = AnswersVersion
		if answers.Source.TLSCASourceFile == "" {
			// A v1 path may already contain the certificate on a configured host. The installer
			// checks that location or asks for --ca-file during repair; it never guesses another.
			answers.Source.TLSCASourceFile = answers.Source.TLSCAFile
		}
		answers.Source.Executor = config.Credential{}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Answers{}, fmt.Errorf("init: answers file must contain exactly one YAML document")
	}
	return answers, nil
}

// Interactive collects references and deployment metadata only. Both modes call Generate,
// which is what guarantees byte-for-byte parity for identical Answers.
func Interactive(in io.Reader, out io.Writer, initial Answers) (Answers, error) {
	reader := bufio.NewReader(in)
	questions := []struct {
		label        string
		help         string
		defaultValue string
		assign       func(string) error
	}{
		{label: "Output directory", defaultValue: defaultString(initial.OutputDirectory, defaultOutputDirectory()), assign: func(value string) error { initial.OutputDirectory = value; return nil }},
		{label: "Organization UUID", defaultValue: initial.OrganizationID, assign: func(value string) error { initial.OrganizationID = value; return nil }},
		{label: "PostgreSQL host", defaultValue: initial.Source.Host, assign: func(value string) error { initial.Source.Host = value; return nil }},
		{label: "PostgreSQL port", defaultValue: defaultString(strconv.Itoa(initial.Source.Port), "5432"), assign: func(value string) error {
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("port must be an integer")
			}
			initial.Source.Port = port
			return nil
		}},
		{label: "Database", defaultValue: initial.Source.Database, assign: func(value string) error { initial.Source.Database = value; return nil }},
		{
			label: "PostgreSQL CA certificate (source path)",
			// An operator who does not already know this answer cannot invent it, and pressing
			// Enter used to be accepted here — the refusal arrived at `install`, one step and
			// often one machine later, phrased as a missing bundle input. The question now
			// carries what it is, where it usually already exists, and why it cannot be skipped.
			help: postgresCAHelp,
			// Offered, never assumed: the discovered path is shown as the default and can be
			// replaced. Guessing silently would point verify-full at the wrong authority.
			defaultValue: defaultString(initial.Source.TLSCASourceFile, discoverPostgresCA()),
			assign: func(value string) error {
				if value == "" {
					return errors.New("required — the connector verifies your database against this certificate before it will hold delete rights on it")
				}
				if _, err := os.Stat(value); err != nil {
					// Not an error: a bundle is often prepared by whoever owns the certificate and
					// installed by someone else, on another host. Silence would be worse than a
					// note — a typo and a legitimately remote path look identical here.
					fmt.Fprintf(out, "  note: not readable on this machine — expected if the bundle is installed elsewhere\n")
				}
				initial.Source.TLSCASourceFile = value
				return nil
			},
		},
		{label: "Reader role", defaultValue: defaultString(initial.Source.Reader.Username, "retentionops_reader"), assign: func(value string) error { initial.Source.Reader.Username = value; return nil }},
		{label: "Reader secret provider", defaultValue: defaultString(initial.Source.Reader.Password.Provider, "file"), assign: func(value string) error { initial.Source.Reader.Password.Provider = value; return nil }},
		{label: "Reader secret reference", defaultValue: defaultString(initial.Source.Reader.Password.Ref, "/etc/retentionops/secrets/reader-password"), assign: func(value string) error { initial.Source.Reader.Password.Ref = value; return nil }},
		{label: "Allowed schemas (comma separated)", defaultValue: strings.Join(initial.Source.AllowedSchemas, ","), assign: func(value string) error {
			initial.Source.AllowedSchemas = splitSchemas(value)
			return nil
		}},
	}
questions:
	for _, question := range questions {
		if question.help != "" {
			if _, err := fmt.Fprintf(out, "\n%s\n", question.help); err != nil {
				return Answers{}, err
			}
		}
		for {
			if _, err := fmt.Fprintf(out, "%s [%s]: ", question.label, question.defaultValue); err != nil {
				return Answers{}, err
			}
			value, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return Answers{}, fmt.Errorf("init: read answer: %w", err)
			}
			value = strings.TrimSpace(value)
			if value == "" {
				value = question.defaultValue
			}
			if assignErr := question.assign(value); assignErr != nil {
				// A rejected answer is re-asked rather than ending the run: losing nine correct
				// answers to one typo is what makes an operator paste a value to get past the
				// prompt. On EOF there is nobody left to re-ask, so the error stands.
				if errors.Is(err, io.EOF) {
					return Answers{}, fmt.Errorf("init: %s: %w", question.label, assignErr)
				}
				if _, err := fmt.Fprintf(out, "  %v\n", assignErr); err != nil {
					return Answers{}, err
				}
				continue
			}
			if errors.Is(err, io.EOF) {
				break questions
			}
			break
		}
	}
	return initial, nil
}

const postgresCAHelp = `The CA certificate that signed your PostgreSQL server's TLS certificate — a path on this
machine. The connector verifies the server against it on every connection, because it holds
delete rights on your data and an unverified connection is one somebody can stand in the
middle of. Usually already present as ssl_ca_file in postgresql.conf, as ~/.postgresql/root.crt,
or as /etc/ssl/certs/ca-certificates.crt if the server uses a publicly trusted certificate.`

// discoverPostgresCA returns the first conventional location that exists, most specific first.
// The system bundle is last: it is the right answer only for a publicly trusted server
// certificate, and offering it ahead of a private CA would quietly widen who is trusted.
func discoverPostgresCA() string {
	candidates := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".postgresql", "root.crt"))
	}
	matches, err := filepath.Glob("/etc/postgresql/*/main/root.crt")
	if err == nil {
		candidates = append(candidates, matches...)
	}
	candidates = append(candidates,
		"/var/lib/postgresql/.postgresql/root.crt",
		"/etc/ssl/certs/ca-certificates.crt",
	)
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func defaultOutputDirectory() string {
	working, err := os.Getwd()
	if err == nil && filepath.Base(working) == "retentionops-connector-init" {
		return "."
	}
	return "./retentionops-connector-init"
}

func defaultString(value, fallback string) string {
	if value == "" || value == "0" {
		return fallback
	}
	return value
}

func splitSchemas(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if schema := strings.TrimSpace(part); schema != "" {
			result = append(result, schema)
		}
	}
	return result
}

// Generate writes a private, deterministic installation bundle. Existing credential files are
// never overwritten: rerunning init may update generated configuration, but cannot erase a
// secret an operator has already installed.
func Generate(answers Answers) error {
	if answers.Source.TLSCAFile == "" {
		answers.Source.TLSCAFile = "/etc/retentionops/certs/postgres-ca.pem"
	}
	configuration, err := buildConfig(answers)
	if err != nil {
		return err
	}
	if answers.Version != AnswersVersion {
		return fmt.Errorf("init: answers version %d is unsupported; expected %d", answers.Version, AnswersVersion)
	}
	if answers.Platform != PlatformSystemd && answers.Platform != PlatformCompose {
		return fmt.Errorf("init: platform must be systemd or compose")
	}
	if answers.OrganizationID != "" && !uuidPattern.MatchString(answers.OrganizationID) {
		return fmt.Errorf("init: organization_id is not a lowercase UUID")
	}
	if answers.OutputDirectory == "" {
		return fmt.Errorf("init: output_directory is required")
	}
	output, err := filepath.Abs(answers.OutputDirectory)
	if err != nil {
		return fmt.Errorf("init: resolve output directory: %w", err)
	}
	if err := prepareOutputDirectory(output); err != nil {
		return err
	}

	configurationYAML, err := yaml.Marshal(configuration)
	if err != nil {
		return fmt.Errorf("init: render connector.yaml: %w", err)
	}
	artifacts := map[string][]byte{
		"connector.yaml": configurationYAML,
		"roles.sql": []byte(postgres.RenderRolesSQL(
			answers.Source.Database,
			answers.Source.Reader,
			answers.Source.Executor,
			answers.Source.AllowedSchemas,
		)),
		"NEXT-STEPS.txt": []byte(renderNextSteps(answers)),
	}
	if answers.Platform == PlatformSystemd {
		artifacts["retentionops-connector.service"] = []byte(systemdUnit)
	} else {
		artifacts["compose.yaml"] = []byte(renderCompose(answers))
		// compose.yaml bind-mounts the CA certificate from here. Without the directory Docker
		// would create one in its place and the source check would fail on an unreadable file.
		if err := os.MkdirAll(filepath.Join(output, "certs"), 0o700); err != nil {
			return fmt.Errorf("init: create certificates directory: %w", err)
		}
	}
	for name, content := range artifacts {
		if err := writeFile(filepath.Join(output, name), content, 0o600); err != nil {
			return err
		}
	}
	manifest := BundleManifest{
		Version: BundleVersion, Platform: answers.Platform, OrganizationID: answers.OrganizationID,
		SourceID: answers.SourceID, ControlPlaneURL: answers.ControlPlane.URL,
		RuntimeConfig: runtimeConfigPath,
		PostgreSQL: BundlePostgreSQL{
			Host: answers.Source.Host, Port: answers.Source.Port, Database: answers.Source.Database,
			CASourceFile: answers.Source.TLSCASourceFile, CARuntimeFile: answers.Source.TLSCAFile,
		},
		Artifacts: make(map[string]string, len(artifacts)),
	}
	for name, content := range artifacts {
		digest := sha256.Sum256(content)
		manifest.Artifacts[name] = "sha256:" + hex.EncodeToString(digest[:])
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("init: render bundle.json: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeFile(filepath.Join(output, "bundle.json"), encoded, 0o600); err != nil {
		return err
	}
	return nil
}

// LoadBundle verifies the manifest and every generated artifact before an installer trusts it.
func LoadBundle(directory string) (BundleManifest, string, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return BundleManifest{}, "", fmt.Errorf("bundle: resolve directory: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "bundle.json")) //nolint:gosec // operator-supplied bundle
	if errors.Is(err, os.ErrNotExist) {
		return loadLegacyBundle(root)
	}
	if err != nil {
		return BundleManifest{}, "", fmt.Errorf("bundle: read bundle.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest BundleManifest
	if err := decoder.Decode(&manifest); err != nil {
		return BundleManifest{}, "", fmt.Errorf("bundle: parse bundle.json: %w", err)
	}
	if manifest.Version != BundleVersion {
		return BundleManifest{}, "", fmt.Errorf("bundle: version %d is unsupported", manifest.Version)
	}
	if manifest.Platform != PlatformSystemd && manifest.Platform != PlatformCompose {
		return BundleManifest{}, "", fmt.Errorf("bundle: platform %q is unsupported", manifest.Platform)
	}
	for name, expected := range manifest.Artifacts {
		if filepath.Base(name) != name {
			return BundleManifest{}, "", fmt.Errorf("bundle: artifact %q is not a local filename", name)
		}
		content, readErr := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // manifest confines basename
		if readErr != nil {
			return BundleManifest{}, "", fmt.Errorf("bundle: read %s: %w", name, readErr)
		}
		digest := sha256.Sum256(content)
		actual := "sha256:" + hex.EncodeToString(digest[:])
		if actual != expected {
			return BundleManifest{}, "", fmt.Errorf("bundle: %s digest mismatch", name)
		}
	}
	return manifest, root, nil
}

// loadLegacyBundle gives v1 init directories one narrow migration path. The marker and strict
// configuration are required, then the first install records digests in a v1 manifest. Existing
// identities and runtime files are outside this bundle and are never touched by the migration.
func loadLegacyBundle(root string) (BundleManifest, string, error) {
	if _, err := os.Stat(filepath.Join(root, ".retentionops-init-v1")); err != nil {
		return BundleManifest{}, "", errors.New("bundle: bundle.json is missing and this is not a legacy init bundle")
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm()&fs.FileMode(0o077) != 0 {
		return BundleManifest{}, "", errors.New("bundle: legacy init directory must be private")
	}
	configuration, err := config.Load(filepath.Join(root, "connector.yaml"))
	if err != nil {
		return BundleManifest{}, "", fmt.Errorf("bundle: legacy connector.yaml: %w", err)
	}
	if len(configuration.Sources) != 1 {
		return BundleManifest{}, "", errors.New("bundle: legacy init bundle must contain exactly one source")
	}
	platform := PlatformSystemd
	platformArtifact := "retentionops-connector.service"
	if _, err := os.Stat(filepath.Join(root, "compose.yaml")); err == nil {
		platform = PlatformCompose
		platformArtifact = "compose.yaml"
	}
	var sourceID string
	var source *config.Source
	for sourceID, source = range configuration.Sources {
		break
	}
	manifest := BundleManifest{
		Version: BundleVersion, Platform: platform, SourceID: sourceID,
		ControlPlaneURL: configuration.ControlPlane.URL, RuntimeConfig: runtimeConfigPath,
		PostgreSQL: BundlePostgreSQL{
			Host: source.Host, Port: source.Port, Database: source.Database,
			CARuntimeFile: source.TLS.CAFile,
		},
		Artifacts: map[string]string{},
	}
	for _, name := range []string{"connector.yaml", "roles.sql", "NEXT-STEPS.txt", platformArtifact} {
		content, readErr := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // fixed legacy bundle artifact
		if readErr != nil {
			return BundleManifest{}, "", fmt.Errorf("bundle: legacy artifact %s: %w", name, readErr)
		}
		sum := sha256.Sum256(content)
		manifest.Artifacts[name] = "sha256:" + hex.EncodeToString(sum[:])
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BundleManifest{}, "", err
	}
	if err := writeFile(filepath.Join(root, "bundle.json"), append(encoded, '\n'), 0o600); err != nil {
		return BundleManifest{}, "", fmt.Errorf("bundle: record legacy migration: %w", err)
	}
	return manifest, root, nil
}

const bundleMarker = ".retentionops-init-v2"

func prepareOutputDirectory(output string) error {
	info, err := os.Stat(output)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(output, 0o700); err != nil {
			return fmt.Errorf("init: create output directory: %w", err)
		}
		if err := os.Chmod(output, 0o700); err != nil {
			return fmt.Errorf("init: protect output directory: %w", err)
		}
	case err != nil:
		return fmt.Errorf("init: inspect output directory: %w", err)
	case !info.IsDir():
		return fmt.Errorf("init: output path is not a directory")
	case info.Mode().Perm()&fs.FileMode(0o077) != 0:
		return fmt.Errorf("init: existing output directory is not private (mode %#o)", info.Mode().Perm())
	default:
		entries, readErr := os.ReadDir(output)
		if readErr != nil {
			return fmt.Errorf("init: inspect output directory: %w", readErr)
		}
		if len(entries) > 0 {
			if _, markerErr := os.Stat(filepath.Join(output, bundleMarker)); markerErr != nil {
				return fmt.Errorf("init: existing non-empty directory is not an init bundle")
			}
		}
	}
	return writeFile(filepath.Join(output, bundleMarker), []byte("retentionops connector init bundle v2\n"), 0o600)
}

func buildConfig(answers Answers) (*config.Config, error) {
	configuration := &config.Config{
		ControlPlane: config.ControlPlane{
			URL: answers.ControlPlane.URL, PollWaitSeconds: 30, HeartbeatSeconds: 30,
			CAFile: answers.ControlPlane.CAFile,
		},
		Identity:  config.Storage{Directory: identityDirectory},
		State:     config.Storage{Directory: stateDirectory},
		Telemetry: config.Telemetry{MetricsAddress: "127.0.0.1:9102", LogFormat: "json", LogLevel: "info"},
		Sources: map[string]*config.Source{
			answers.SourceID: {
				Type: "postgresql", Mode: config.SourceModeDiscoveryOnly,
				Host: answers.Source.Host, Port: answers.Source.Port,
				Database: answers.Source.Database,
				TLS:      config.TLS{Mode: config.TLSVerifyFull, CAFile: answers.Source.TLSCAFile},
				Reader:   answers.Source.Reader,
				Safety: policy.Safety{
					AllowedSchemas: answers.Source.AllowedSchemas, RequireApproval: true,
					Drift:         policy.DriftPolicy{Mode: "bounded", ExactMatchBelowRows: 1000, MaxRows: 100, MaxBasisPoints: 50},
					MaxDeleteRows: 10_000, MaxBatchSize: 250,
					StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 1800,
					Tables: []policy.TableRule{},
				},
			},
		},
	}
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("init: generated configuration is invalid: %w", err)
	}
	return configuration, nil
}

func writeFile(path string, content []byte, mode fs.FileMode) error {
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("init: write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("init: protect %s: %w", path, err)
	}
	return nil
}

// renderNextSteps writes the remaining commands with the paths this bundle actually declares.
//
// The generated configuration resolves secrets, the CA certificate and the connector identity at
// runtime paths that do not exist yet, and — on systemd — under a service account that does not
// exist yet either. A guide that skipped those steps would fail on the first `source test`, which
// is exactly the moment an operator has no way to tell a missing directory from a refusal.
func renderNextSteps(answers Answers) string {
	activation := "sudo systemctl enable --now retentionops-connector"
	if answers.Platform == PlatformCompose {
		activation = `docker compose -f "$PWD/compose.yaml" up -d`
	}
	return fmt.Sprintf(`RetentionOps connector — reviewed local installation

init did not execute SQL, create a secret, contact RetentionOps, install a service or start one.
The generated source is discovery-only: no executor credential and no DELETE grant exist.

1. Review connector.yaml, roles.sql and bundle.json.
2. Enter this bundle directory and run the resumable local assistant:
   sudo retentionops-connector install --bundle "$PWD"
3. After the assistant reports every check green, perform its one explicit activation command:
   %s

The assistant prints the exact DBA command for %s:%d/%s. It never emits a password, token,
generic host placeholder or command containing a secret.
`, activation, answers.Source.Host, answers.Source.Port, answers.Source.Database)
}

const systemdUnit = `[Unit]
Description=RetentionOps Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=retentionops
Group=retentionops
ExecStart=/usr/bin/retentionops-connector run --config /etc/retentionops/connector.yaml
Restart=on-failure
RestartSec=5s
StateDirectory=retentionops
StateDirectoryMode=0700
ReadWritePaths=/var/lib/retentionops
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
`

func renderCompose(answers Answers) string {
	return fmt.Sprintf(`services:
  connector:
    image: %s@sha256:REPLACE_WITH_VERIFIED_DIGEST
    command: ["run", "--config", %q]
    restart: unless-stopped
    user: "65532:65532"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - ./connector.yaml:%s:ro
      - ./runtime/certs/postgres-ca.pem:%s:ro
      - ./runtime/secrets/reader-password:%s:ro
      - ./runtime/identity:/var/lib/retentionops/identity
      - ./runtime/state:/var/lib/retentionops/state
    networks: [egress, database]

networks:
  egress:
  database:
    external: true
`, imageRepository, runtimeConfigPath, runtimeConfigPath, answers.Source.TLSCAFile, answers.Source.Reader.Password.Ref)
}

// ValidateControlPlaneFlag provides a fast error before prompting while Config.Validate remains
// the executable authority used for the generated artifact.
func ValidateControlPlaneFlag(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("--control-plane must be an https URL")
	}
	return nil
}

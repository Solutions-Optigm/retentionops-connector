// Package initializer renders a reviewable connector installation without executing it.
//
// The generated directory is an operator-owned handoff: no SQL is applied, no service is
// installed, no enrollment is attempted and no configuration crosses the network.
package initializer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	"gopkg.in/yaml.v3"
)

const (
	// AnswersVersion is bumped whenever an answers file would otherwise change meaning.
	AnswersVersion  = 1
	PlatformSystemd = "systemd"
	PlatformCompose = "compose"
)

// Answers is the strict, versioned input shared by interactive and unattended initialization.
// Credential fields are SecretRef values, so there is deliberately nowhere to put a secret.
type Answers struct {
	Version         int          `yaml:"version"`
	Platform        string       `yaml:"platform"`
	OutputDirectory string       `yaml:"output_directory"`
	SourceID        string       `yaml:"source_id"`
	ControlPlane    ControlPlane `yaml:"control_plane"`
	Source          Source       `yaml:"source"`
}

type ControlPlane struct {
	URL    string `yaml:"url"`
	CAFile string `yaml:"ca_file,omitempty"`
}

type Source struct {
	Host           string            `yaml:"host"`
	Port           int               `yaml:"port"`
	Database       string            `yaml:"database"`
	TLSCAFile      string            `yaml:"tls_ca_file"`
	Reader         config.Credential `yaml:"reader"`
	Executor       config.Credential `yaml:"executor"`
	AllowedSchemas []string          `yaml:"allowed_schemas"`
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
		defaultValue string
		assign       func(string) error
	}{
		{"Output directory", defaultString(initial.OutputDirectory, "./retentionops-connector-init"), func(value string) error { initial.OutputDirectory = value; return nil }},
		{"PostgreSQL host", initial.Source.Host, func(value string) error { initial.Source.Host = value; return nil }},
		{"PostgreSQL port", defaultString(strconv.Itoa(initial.Source.Port), "5432"), func(value string) error {
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("port must be an integer")
			}
			initial.Source.Port = port
			return nil
		}},
		{"Database", initial.Source.Database, func(value string) error { initial.Source.Database = value; return nil }},
		{"PostgreSQL CA file (runtime path)", initial.Source.TLSCAFile, func(value string) error { initial.Source.TLSCAFile = value; return nil }},
		{"Reader role", defaultString(initial.Source.Reader.Username, "retentionops_reader"), func(value string) error { initial.Source.Reader.Username = value; return nil }},
		{"Reader secret provider", defaultString(initial.Source.Reader.Password.Provider, "file"), func(value string) error { initial.Source.Reader.Password.Provider = value; return nil }},
		{"Reader secret reference", defaultString(initial.Source.Reader.Password.Ref, "/etc/retentionops/secrets/reader-password"), func(value string) error { initial.Source.Reader.Password.Ref = value; return nil }},
		{"Executor role", defaultString(initial.Source.Executor.Username, "retentionops_executor"), func(value string) error { initial.Source.Executor.Username = value; return nil }},
		{"Executor secret provider", defaultString(initial.Source.Executor.Password.Provider, "file"), func(value string) error { initial.Source.Executor.Password.Provider = value; return nil }},
		{"Executor secret reference", defaultString(initial.Source.Executor.Password.Ref, "/etc/retentionops/secrets/executor-password"), func(value string) error { initial.Source.Executor.Password.Ref = value; return nil }},
		{"Allowed schemas (comma separated)", strings.Join(initial.Source.AllowedSchemas, ","), func(value string) error {
			initial.Source.AllowedSchemas = splitSchemas(value)
			return nil
		}},
	}
	for _, question := range questions {
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
		if err := question.assign(value); err != nil {
			return Answers{}, fmt.Errorf("init: %s: %w", question.label, err)
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return initial, nil
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
	}
	for name, content := range artifacts {
		if err := writeFile(filepath.Join(output, name), content, 0o600); err != nil {
			return err
		}
	}
	for _, credential := range []config.Credential{answers.Source.Reader, answers.Source.Executor} {
		if credential.Password.Provider != "file" {
			continue
		}
		name := filepath.Base(filepath.Clean(credential.Password.Ref))
		if name == "." || name == string(filepath.Separator) {
			return fmt.Errorf("init: file secret reference %q has no filename", credential.Password.Ref)
		}
		if err := createSecretPlaceholder(filepath.Join(output, "secrets", name)); err != nil {
			return err
		}
	}
	if err := createSecretPlaceholder(filepath.Join(output, "secrets", "enrollment-token")); err != nil {
		return err
	}
	return nil
}

const bundleMarker = ".retentionops-init-v1"

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
	return writeFile(filepath.Join(output, bundleMarker), []byte("retentionops connector init bundle v1\n"), 0o600)
}

func buildConfig(answers Answers) (*config.Config, error) {
	configuration := &config.Config{
		ControlPlane: config.ControlPlane{
			URL: answers.ControlPlane.URL, PollWaitSeconds: 30, HeartbeatSeconds: 30,
			CAFile: answers.ControlPlane.CAFile,
		},
		Identity:  config.Storage{Directory: "/var/lib/retentionops/identity"},
		State:     config.Storage{Directory: "/var/lib/retentionops/state"},
		Telemetry: config.Telemetry{MetricsAddress: "127.0.0.1:9102", LogFormat: "json", LogLevel: "info"},
		Sources: map[string]*config.Source{
			answers.SourceID: {
				Type: "postgresql", Host: answers.Source.Host, Port: answers.Source.Port,
				Database: answers.Source.Database,
				TLS:      config.TLS{Mode: config.TLSVerifyFull, CAFile: answers.Source.TLSCAFile},
				Reader:   answers.Source.Reader, Executor: answers.Source.Executor,
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

func createSecretPlaceholder(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("init: create secrets directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("init: protect secrets directory: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o400); err != nil {
			return fmt.Errorf("init: protect secret placeholder: %w", err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("init: inspect secret placeholder: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // fixed private mode
	if err != nil {
		return fmt.Errorf("init: create secret placeholder: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("init: close secret placeholder: %w", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return fmt.Errorf("init: protect secret placeholder: %w", err)
	}
	return nil
}

func renderNextSteps(answers Answers) string {
	service := "sudo install -m 0600 connector.yaml /etc/retentionops/connector.yaml\n" +
		"sudo install -m 0644 retentionops-connector.service /etc/systemd/system/retentionops-connector.service\n" +
		"sudo systemctl enable --now retentionops-connector\n"
	if answers.Platform == PlatformCompose {
		service = "docker compose -f compose.yaml up -d\n"
	}
	return fmt.Sprintf(`RetentionOps connector — next steps

1. Review connector.yaml and roles.sql. No table is authorized for deletion.
2. Put the database passwords in the matching files under secrets/ (mode 0400).
3. Apply roles.sql yourself with psql; init never executes SQL.
4. retentionops-connector validate-config --config connector.yaml
5. retentionops-connector source test --config connector.yaml %s
6. retentionops-connector source discover --config connector.yaml %s
7. Request a single-use enrollment token in the console and save it to secrets/enrollment-token.
8. retentionops-connector enroll --config connector.yaml --url %s --organization ORGANIZATION_UUID --token-file secrets/enrollment-token
9. retentionops-connector doctor --config connector.yaml
10. Start the supervised service:
%s
The connector has not contacted RetentionOps and no service has been installed or started.
`, answers.SourceID, answers.SourceID, answers.ControlPlane.URL, service)
}

const systemdUnit = `[Unit]
Description=RetentionOps Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=retentionops
Group=retentionops
ExecStart=/usr/local/bin/retentionops-connector run --config /etc/retentionops/connector.yaml
Restart=on-failure
RestartSec=5s
StateDirectory=retentionops
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
`

func renderCompose(answers Answers) string {
	secretMounts := make([]string, 0, 2)
	secretDefinitions := make([]string, 0, 2)
	for name, credential := range map[string]config.Credential{"reader": answers.Source.Reader, "executor": answers.Source.Executor} {
		if credential.Password.Provider != "file" {
			continue
		}
		filename := filepath.Base(filepath.Clean(credential.Password.Ref))
		secretMounts = append(secretMounts, fmt.Sprintf("      - source: postgres_%s_password\n        target: %s\n        mode: 0400", name, credential.Password.Ref))
		secretDefinitions = append(secretDefinitions, fmt.Sprintf("  postgres_%s_password:\n    file: ./secrets/%s", name, filename))
	}
	slices.Sort(secretMounts)
	slices.Sort(secretDefinitions)
	secretsBlock := ""
	serviceSecrets := ""
	if len(secretMounts) > 0 {
		serviceSecrets = "\n    secrets:\n" + strings.Join(secretMounts, "\n")
		secretsBlock = "\nsecrets:\n" + strings.Join(secretDefinitions, "\n") + "\n"
	}
	return fmt.Sprintf(`services:
  connector:
    image: ghcr.io/solutions-optigm/retentionops-connector@sha256:REPLACE_WITH_VERIFIED_DIGEST
    command: ["run", "--config", "/etc/retentionops/connector.yaml"]
    restart: unless-stopped
    user: "65532:65532"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - ./connector.yaml:/etc/retentionops/connector.yaml:ro
      - state:/var/lib/retentionops
    networks: [egress, database]%s

volumes:
  state:

networks:
  egress:
  database:
    external: true
%s`, serviceSecrets, secretsBlock)
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

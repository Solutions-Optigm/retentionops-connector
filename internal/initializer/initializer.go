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
		Identity:  config.Storage{Directory: identityDirectory},
		State:     config.Storage{Directory: stateDirectory},
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

// renderNextSteps writes the remaining commands with the paths this bundle actually declares.
//
// The generated configuration resolves secrets, the CA certificate and the connector identity at
// runtime paths that do not exist yet, and — on systemd — under a service account that does not
// exist yet either. A guide that skipped those steps would fail on the first `source test`, which
// is exactly the moment an operator has no way to tell a missing directory from a refusal.
func renderNextSteps(answers Answers) string {
	if answers.Platform == PlatformCompose {
		return composeNextSteps(answers)
	}
	return systemdNextSteps(answers)
}

// stagedCredentials lists the roles whose password init staged as a local file. A role resolved
// through a secret manager has nothing to fill in and must not be told to write one.
func stagedCredentials(answers Answers) []string {
	staged := make([]string, 0, 2)
	for _, candidate := range []struct {
		name       string
		credential config.Credential
	}{{"reader", answers.Source.Reader}, {"executor", answers.Source.Executor}} {
		if candidate.credential.Password.Provider == "file" {
			staged = append(staged, candidate.name)
		}
	}
	return staged
}

// fillSecrets keeps the passwords out of shell history and out of process arguments. The staged
// placeholders are mode 0400, so they are deliberately relaxed and restored around the write.
func fillSecrets(answers Answers) string {
	staged := stagedCredentials(answers)
	if len(staged) == 0 {
		return "   Both roles resolve their password through the configured secret provider; there is\n   no local file to fill in."
	}
	files := make([]string, 0, len(staged))
	writes := make([]string, 0, len(staged))
	for _, name := range staged {
		files = append(files, "secrets/"+name+"-password")
		writes = append(writes, fmt.Sprintf(
			`   read -rsp '%s password: ' password && printf '%%s' "$password" > secrets/%s-password && unset password && echo`,
			name, name))
	}
	lines := append([]string{"   chmod 0600 " + strings.Join(files, " ")}, writes...)
	return strings.Join(append(lines, "   chmod 0400 "+strings.Join(files, " ")), "\n")
}

func systemdNextSteps(answers Answers) string {
	installed := make([]string, 0, 3)
	if answers.Source.TLSCAFile != "" {
		installed = append(installed, fmt.Sprintf(
			"\n   sudo install -o root -g retentionops -m 0644 YOUR-POSTGRES-CA.pem %s", answers.Source.TLSCAFile))
	}
	references := map[string]config.SecretRef{
		"reader":   answers.Source.Reader.Password,
		"executor": answers.Source.Executor.Password,
	}
	for _, name := range stagedCredentials(answers) {
		installed = append(installed, fmt.Sprintf(
			"\n   sudo install -o retentionops -g retentionops -m 0400 secrets/%s-password %s",
			name, references[name].Ref))
	}
	return fmt.Sprintf(`RetentionOps connector — next steps (systemd)

Everything below runs on this host. init executed no SQL, contacted no network and started
nothing; each command here is yours to review before you run it.

1. Review connector.yaml and roles.sql. No table is authorized for deletion.
2. Create the service account and the directories the connector reads and writes:
   id retentionops >/dev/null 2>&1 || sudo useradd --system --home-dir /var/lib/retentionops --shell /usr/sbin/nologin retentionops
   sudo install -d -o retentionops -g retentionops -m 0700 %s %s
   sudo install -d -o root -g retentionops -m 0750 /etc/retentionops /etc/retentionops/certs /etc/retentionops/secrets
3. Create the database roles yourself; init never executes SQL. psql prompts for both passwords:
   psql "postgresql://ADMIN_ROLE@%s:%d/%s" -f roles.sql
4. Write the same two passwords into the staged secret files:
%s
5. Install the configuration, the CA certificate and the secrets at the paths connector.yaml
   declares — the connector reads them there, not from this directory:
   sudo install -o root -g retentionops -m 0640 connector.yaml /etc/retentionops/connector.yaml%s
6. sudo -u retentionops retentionops-connector validate-config --config %s
7. sudo -u retentionops retentionops-connector source test --config %s %s
8. sudo -u retentionops retentionops-connector source discover --config %s %s
9. Request a single-use enrollment token in the console, then save it where the service account
   can read it once. Paste it into the second command and end with Ctrl-D; a token typed as an
   argument would survive in shell history:
   sudo install -o retentionops -g retentionops -m 0400 /dev/null /etc/retentionops/secrets/enrollment-token
   sudo sh -c 'cat > /etc/retentionops/secrets/enrollment-token'
10. sudo -u retentionops retentionops-connector enroll --config %s --url %s --organization ORGANIZATION_UUID --token-file /etc/retentionops/secrets/enrollment-token
11. sudo rm -f /etc/retentionops/secrets/enrollment-token
12. sudo -u retentionops retentionops-connector doctor --config %s
13. Start the supervised service:
   sudo install -o root -g root -m 0644 retentionops-connector.service /etc/systemd/system/retentionops-connector.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now retentionops-connector
   sudo systemctl status retentionops-connector

The connector has not contacted RetentionOps and no service has been installed or started.
`,
		identityDirectory, stateDirectory,
		answers.Source.Host, answers.Source.Port, answers.Source.Database,
		fillSecrets(answers),
		strings.Join(installed, ""),
		runtimeConfigPath,
		runtimeConfigPath, answers.SourceID,
		runtimeConfigPath, answers.SourceID,
		runtimeConfigPath, answers.ControlPlane.URL,
		runtimeConfigPath)
}

func composeNextSteps(answers Answers) string {
	steps := []string{
		"Review connector.yaml and roles.sql. No table is authorized for deletion.",
		fmt.Sprintf(`Create the database roles yourself; init never executes SQL. psql prompts for both passwords:
   psql "postgresql://ADMIN_ROLE@%s:%d/%s" -f roles.sql`,
			answers.Source.Host, answers.Source.Port, answers.Source.Database),
		"Write the same two passwords into the staged secret files:\n" + fillSecrets(answers),
		fmt.Sprintf(`Verify the image, then pin the digest compose.yaml expects — a tag can be moved, a digest cannot:
   digest=$(docker buildx imagetools inspect %s:latest --format '{{.Manifest.Digest}}')
   sed -i "s|@sha256:REPLACE_WITH_VERIFIED_DIGEST|@${digest}|" compose.yaml`, imageRepository),
		`Attach the connector to the network that reaches PostgreSQL. compose.yaml expects an
   existing network named "database"; rename it there, or create it:
   docker network create database`,
	}
	if answers.Source.TLSCAFile != "" {
		steps = append(steps, fmt.Sprintf(
			"Copy your PostgreSQL CA certificate to certs/%s; compose.yaml mounts it read-only at %s.",
			filepath.Base(filepath.Clean(answers.Source.TLSCAFile)), answers.Source.TLSCAFile))
	}
	steps = append(steps,
		fmt.Sprintf("docker compose run --rm connector validate-config --config %s", runtimeConfigPath),
		fmt.Sprintf("docker compose run --rm connector source test --config %s %s", runtimeConfigPath, answers.SourceID),
		fmt.Sprintf("docker compose run --rm connector source discover --config %s %s", runtimeConfigPath, answers.SourceID),
		`Request a single-use enrollment token in the console and save it to secrets/enrollment-token
   (chmod 0600 to write it, chmod 0400 afterwards).`,
		fmt.Sprintf(`docker compose run --rm -v "$PWD/secrets/enrollment-token:/run/enrollment-token:ro" connector \
      enroll --config %s --url %s --organization ORGANIZATION_UUID --token-file /run/enrollment-token`,
			runtimeConfigPath, answers.ControlPlane.URL),
		fmt.Sprintf("docker compose run --rm connector doctor --config %s", runtimeConfigPath),
		"docker compose up -d",
	)
	numbered := make([]string, 0, len(steps))
	for index, step := range steps {
		numbered = append(numbered, fmt.Sprintf("%d. %s", index+1, step))
	}
	return fmt.Sprintf(`RetentionOps connector — next steps (Docker Compose)

Everything below runs in this directory. init executed no SQL, contacted no network and started
nothing; each command here is yours to review before you run it.

%s

The connector has not contacted RetentionOps and no service has been installed or started.
`, strings.Join(numbered, "\n"))
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
	// The configuration pins TLS verify-full against a CA file the container cannot see unless
	// this file mounts it. Without the mount the first source check fails on a missing file, and
	// the obvious workaround — weakening TLS — is the one an operator must never be nudged into.
	certificates := make([]string, 0, 2)
	for _, authority := range []string{answers.Source.TLSCAFile, answers.ControlPlane.CAFile} {
		if authority == "" {
			continue
		}
		certificates = append(certificates, fmt.Sprintf("\n      - ./certs/%s:%s:ro",
			filepath.Base(filepath.Clean(authority)), authority))
	}
	slices.Sort(certificates)
	certificates = slices.Compact(certificates)
	secretsBlock := ""
	serviceSecrets := ""
	if len(secretMounts) > 0 {
		serviceSecrets = "\n    secrets:\n" + strings.Join(secretMounts, "\n")
		secretsBlock = "\nsecrets:\n" + strings.Join(secretDefinitions, "\n") + "\n"
	}
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
      - ./connector.yaml:%s:ro%s
      - state:/var/lib/retentionops
    networks: [egress, database]%s

volumes:
  state:

networks:
  egress:
  database:
    external: true
%s`, imageRepository, runtimeConfigPath, runtimeConfigPath, strings.Join(certificates, ""), serviceSecrets, secretsBlock)
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

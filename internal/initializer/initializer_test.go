package initializer

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
)

const testSourceID = "4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52"

func validAnswers(output, platform string) Answers {
	return Answers{
		Version: AnswersVersion, Platform: platform, OutputDirectory: output, SourceID: testSourceID,
		OrganizationID: "d0555ae5-d89f-41e8-ba24-31d238ffb8c8",
		ControlPlane:   ControlPlane{URL: "https://connector.retentionops.example"},
		Source: Source{
			Host: "postgres.internal", Port: 5432, Database: "application",
			TLSCASourceFile: "/secure/postgres/ca.crt",
			TLSCAFile:       "/etc/retentionops/certs/postgres-ca.pem",
			Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
				Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
			}},
			AllowedSchemas: []string{"application"},
		},
	}
}

func TestGenerateProducesPrivateNonDestructiveSystemdBundle(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	answers := validAnswers(output, PlatformSystemd)
	if err := Generate(answers); err != nil {
		t.Fatal(err)
	}
	assertMode(t, output, 0o700)
	if _, err := os.Stat(filepath.Join(output, "secrets")); !os.IsNotExist(err) {
		t.Fatal("init must not create empty secret placeholders")
	}
	assertMode(t, filepath.Join(output, "bundle.json"), 0o600)

	configuration, err := config.Load(filepath.Join(output, "connector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Sources[testSourceID].Safety.GrantsDelete() {
		t.Fatal("init must not preselect a destructive table")
	}
	if configuration.Sources[testSourceID].Mode != config.SourceModeDiscoveryOnly {
		t.Fatal("init must generate an explicit discovery-only source")
	}
	roles := read(t, filepath.Join(output, "roles.sql"))
	if strings.Contains(roles, "GRANT DELETE") {
		t.Fatal("roles.sql must not grant destructive access")
	}
	steps := read(t, filepath.Join(output, "NEXT-STEPS.txt"))
	for _, placeholder := range []string{"ADMIN_ROLE", "DB_HOST", "DATABASE", "YOUR-POSTGRES-CA.pem"} {
		if strings.Contains(steps, placeholder) {
			t.Fatalf("installation instructions contain placeholder %s", placeholder)
		}
	}
}

func TestGenerateIsIdempotentAndPreservesInstalledSecrets(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	answers := validAnswers(output, PlatformCompose)
	if err := Generate(answers); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(output, "operator-owned-note")
	if err := os.WriteFile(note, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Generate(answers); err != nil {
		t.Fatal(err)
	}
	if got := read(t, note); got != "keep" {
		t.Fatalf("operator-owned bundle file was overwritten: %q", got)
	}
	compose := read(t, filepath.Join(output, "compose.yaml"))
	if strings.Contains(strings.ToLower(compose), "kubernetes") {
		t.Fatal("the supported Compose bundle must not promise Kubernetes support")
	}
}

// The generated instructions are the whole installation guide once init has run: a step that
// names the staging directory where the connector reads a runtime path sends the operator into a
// missing-file error with no way to tell it apart from a refusal.
func TestNextStepsUseTheRuntimePathsTheConfigurationDeclares(t *testing.T) {
	for _, platform := range []string{PlatformSystemd, PlatformCompose} {
		output := filepath.Join(t.TempDir(), "bundle")
		answers := validAnswers(output, platform)
		if err := Generate(answers); err != nil {
			t.Fatal(err)
		}
		steps := read(t, filepath.Join(output, "NEXT-STEPS.txt"))
		required := []string{"retentionops-connector install --bundle", answers.Source.Host, answers.Source.Database}
		for _, path := range required {
			if !strings.Contains(steps, path) {
				t.Fatalf("%s: NEXT-STEPS.txt never names %s", platform, path)
			}
		}
		if strings.Contains(steps, "--token ") || strings.Contains(steps, "enrollment-token") {
			t.Fatalf("%s: init instructions must not stage enrollment material", platform)
		}
	}
}

// Without this mount the container cannot read the CA the configuration pins, and the shortest
// path out of the resulting failure is downgrading TLS.
func TestComposeMountsTheCertificateTheConfigurationPins(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	answers := validAnswers(output, PlatformCompose)
	if err := Generate(answers); err != nil {
		t.Fatal(err)
	}
	compose := read(t, filepath.Join(output, "compose.yaml"))
	want := "./runtime/certs/postgres-ca.pem:" + answers.Source.TLSCAFile + ":ro"
	if !strings.Contains(compose, want) {
		t.Fatalf("compose.yaml does not mount the pinned CA certificate:\n%s", compose)
	}
	assertMode(t, filepath.Join(output, "certs"), 0o700)
}

func TestInteractiveAndAnswersFileProduceTheSameArtifacts(t *testing.T) {
	fileOutput := filepath.Join(t.TempDir(), "from-file")
	interactiveOutput := filepath.Join(t.TempDir(), "interactive")
	fromFile := validAnswers(fileOutput, PlatformSystemd)
	interactiveSeed := validAnswers(interactiveOutput, PlatformSystemd)
	interactiveSeed.Source = Source{}
	input := strings.Join([]string{
		interactiveOutput,
		fromFile.OrganizationID,
		fromFile.Source.Host,
		"5432",
		fromFile.Source.Database,
		fromFile.Source.TLSCASourceFile,
		fromFile.ControlPlane.CASourceFile,
		fromFile.Source.Reader.Username,
		fromFile.Source.Reader.Password.Provider,
		fromFile.Source.Reader.Password.Ref,
		strings.Join(fromFile.Source.AllowedSchemas, ","),
	}, "\n") + "\n"
	interactive, err := Interactive(strings.NewReader(input), &bytes.Buffer{}, interactiveSeed)
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(fromFile); err != nil {
		t.Fatal(err)
	}
	if err := Generate(interactive); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"connector.yaml", "roles.sql", "retentionops-connector.service", "NEXT-STEPS.txt", "bundle.json"} {
		if !reflect.DeepEqual(readBytes(t, filepath.Join(fileOutput, name)), readBytes(t, filepath.Join(interactiveOutput, name))) {
			t.Fatalf("%s differs between interactive and answers-file inputs", name)
		}
	}
}

func TestLoadAnswersRejectsSecretValuesAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "answers.yaml")
	raw := `version: 1
platform: systemd
output_directory: ./bundle
source_id: 4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52
control_plane:
  url: https://connector.retentionops.example
source:
  password_value: forbidden
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAnswers(path); err == nil || !strings.Contains(err.Error(), "password_value") {
		t.Fatalf("unknown secret value field was not rejected: %v", err)
	}
}

func TestGenerateRefusesToTakeOverAnExistingDirectory(t *testing.T) {
	output := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "owned-by-operator"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Generate(validAnswers(output, PlatformSystemd)); err == nil {
		t.Fatal("init must not overwrite an unrelated existing directory")
	}
}

func TestLoadBundleMigratesAPrivateLegacyInitDirectory(t *testing.T) {
	output := filepath.Join(t.TempDir(), "legacy")
	if err := Generate(validAnswers(output, PlatformSystemd)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(output, "bundle.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(output, bundleMarker), filepath.Join(output, ".retentionops-init-v1")); err != nil {
		t.Fatal(err)
	}
	manifest, migrated, err := LoadBundle(output)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != output || manifest.SourceID != testSourceID || manifest.PostgreSQL.CASourceFile != "" {
		t.Fatalf("unexpected legacy migration: %#v, %s", manifest, migrated)
	}
	assertMode(t, filepath.Join(output, "bundle.json"), 0o600)
	if _, _, err := LoadBundle(output); err != nil {
		t.Fatalf("recorded legacy manifest is not reusable: %v", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	return string(readBytes(t, path))
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestInteractiveRefusesAnEmptyCertificateAndAsksAgain(t *testing.T) {
	// Pressing Enter here used to be accepted, and `install` refused the bundle afterwards —
	// one step later, often on a different machine, naming a bundle input rather than the
	// question that produced it. The refusal belongs where the answer is given.
	seed := validAnswers(t.TempDir(), PlatformSystemd)
	seed.Source = Source{}
	certificate := filepath.Join(t.TempDir(), "postgres-ca.pem")
	if err := os.WriteFile(certificate, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transcript := &bytes.Buffer{}

	answers, err := Interactive(strings.NewReader(strings.Join([]string{
		seed.OutputDirectory, seed.OrganizationID, "postgres.internal", "5432", "application",
		"", // the operator who does not know what to enter
		certificate,
		"", // publicly trusted control plane: nothing to supply
		"retentionops_reader", "file", "/etc/retentionops/secrets/reader-password", "application",
	}, "\n")+"\n"), transcript, seed)
	if err != nil {
		t.Fatal(err)
	}

	if answers.Source.TLSCASourceFile != certificate {
		t.Fatalf("certificate = %q, want %q", answers.Source.TLSCASourceFile, certificate)
	}
	if !strings.Contains(transcript.String(), "required") {
		t.Fatal("an empty answer was accepted without saying the certificate is required")
	}
	if !strings.Contains(transcript.String(), "postgresql.conf") {
		t.Fatal("the question does not say where the certificate usually already exists")
	}
}

func TestInteractiveNotesACertificateThatIsNotReadableHere(t *testing.T) {
	// A bundle is routinely prepared by whoever owns the certificate and installed by someone
	// else. A remote path must stay accepted, but silence would make a typo indistinguishable.
	seed := validAnswers(t.TempDir(), PlatformSystemd)
	seed.Source = Source{}
	transcript := &bytes.Buffer{}

	answers, err := Interactive(strings.NewReader(strings.Join([]string{
		seed.OutputDirectory, seed.OrganizationID, "postgres.internal", "5432", "application",
		"/secure/postgres/ca.crt",
		"", // publicly trusted control plane: nothing to supply
		"retentionops_reader", "file", "/etc/retentionops/secrets/reader-password", "application",
	}, "\n")+"\n"), transcript, seed)
	if err != nil {
		t.Fatal(err)
	}

	if answers.Source.TLSCASourceFile != "/secure/postgres/ca.crt" {
		t.Fatalf("a path absent from this machine was not kept: %q", answers.Source.TLSCASourceFile)
	}
	if !strings.Contains(transcript.String(), "not readable on this machine") {
		t.Fatal("an unreadable certificate path produced no note")
	}
}

// A private control plane is the local and self-hosted shape. Carrying its CA in the bundle is
// what makes `install` reproducible: the alternative is installing the certificate into the
// host's trust store, which no later command can see, verify or reproduce on the next machine.
func TestAPrivateControlPlaneCertificateTravelsWithTheBundle(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	answers := validAnswers(output, PlatformCompose)
	answers.ControlPlane.CASourceFile = "/secure/control-plane/ca.crt"
	if err := Generate(answers); err != nil {
		t.Fatal(err)
	}

	configuration, err := config.Load(filepath.Join(output, "connector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ControlPlane.CAFile != "/etc/retentionops/certs/control-plane-ca.pem" {
		t.Fatalf("control-plane ca_file = %q", configuration.ControlPlane.CAFile)
	}
	compose := read(t, filepath.Join(output, "compose.yaml"))
	want := "./runtime/certs/control-plane-ca.pem:" + configuration.ControlPlane.CAFile + ":ro"
	if !strings.Contains(compose, want) {
		t.Fatalf("compose.yaml does not mount the control-plane CA it pins:\n%s", compose)
	}
	manifest := read(t, filepath.Join(output, "bundle.json"))
	if !strings.Contains(manifest, "/secure/control-plane/ca.crt") {
		t.Fatal("the bundle manifest does not record where to copy the control-plane CA from")
	}
}

// The hosted control plane is publicly trusted. Pinning a file there would make every connector
// depend on a certificate nobody needs to distribute, and break on the first renewal.
func TestAPubliclyTrustedControlPlanePinsNoCertificate(t *testing.T) {
	output := filepath.Join(t.TempDir(), "bundle")
	if err := Generate(validAnswers(output, PlatformCompose)); err != nil {
		t.Fatal(err)
	}

	configuration, err := config.Load(filepath.Join(output, "connector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ControlPlane.CAFile != "" {
		t.Fatalf("an unsupplied control-plane CA became %q", configuration.ControlPlane.CAFile)
	}
	if strings.Contains(read(t, filepath.Join(output, "compose.yaml")), "control-plane-ca.pem") {
		t.Fatal("compose.yaml mounts a control-plane CA that install never writes")
	}
}

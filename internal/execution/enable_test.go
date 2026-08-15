package execution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/initializer"
)

const executionTestSource = "4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52"

func TestExecutionEnableIsAReviewedTwoStepLocalChange(t *testing.T) {
	root := t.TempDir()
	initBundle := filepath.Join(root, "init")
	if err := initializer.Generate(initializer.Answers{
		Version: initializer.AnswersVersion, Platform: initializer.PlatformSystemd,
		OutputDirectory: initBundle, SourceID: executionTestSource,
		OrganizationID: "d0555ae5-d89f-41e8-ba24-31d238ffb8c8",
		ControlPlane:   initializer.ControlPlane{URL: "https://connector.retentionops.example"},
		Source: initializer.Source{
			Host: "127.0.0.1", Port: 5432, Database: "retentionops_test",
			TLSCASourceFile: "/secure/ca.crt", TLSCAFile: "/etc/retentionops/certs/postgres-ca.pem",
			Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
				Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
			}}, AllowedSchemas: []string{"public"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(initBundle, "connector.yaml")
	review := filepath.Join(root, "execution")
	if err := Prepare(PrepareOptions{
		ConfigPath: configPath, SourceID: executionTestSource, ExecutorRole: "retentionops_executor",
		ExecutorSecretRef: "/etc/retentionops/secrets/executor-password",
		Tables:            []Table{{Schema: "public", Name: "tickets", RetentionColumn: "closed_at"}},
		MaxDeleteRows:     10_000, MaxBatchSize: 250, OutputDirectory: review,
	}); err != nil {
		t.Fatal(err)
	}
	live, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if live.Sources[executionTestSource].Mode != config.SourceModeDiscoveryOnly {
		t.Fatal("prepare changed the live local policy")
	}
	roles, err := os.ReadFile(filepath.Join(review, "roles.sql")) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(roles), `GRANT SELECT, DELETE ON TABLE "public"."tickets"`) || strings.Contains(string(roles), "ALL TABLES") {
		t.Fatal("executor SQL is not limited to the reviewed table")
	}
	secret := filepath.Join(root, "executor-password")
	if err := os.WriteFile(secret, []byte("executor-secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ApplyOptions{ConfigPath: configPath, Bundle: review, ExecutorSecretFile: secret}); err != nil {
		t.Fatal(err)
	}
	enabled, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.Sources[executionTestSource].Mode != config.SourceModeExecution || !enabled.Sources[executionTestSource].Safety.GrantsDelete() {
		t.Fatal("reviewed execution policy was not enabled")
	}
}

func TestParseTableRequiresAnExplicitSchemaAndRetentionColumn(t *testing.T) {
	if _, err := ParseTable("tickets"); err == nil {
		t.Fatal("ambiguous table syntax was accepted")
	}
}

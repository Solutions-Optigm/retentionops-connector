package scope_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	"github.com/solutions-optigm/retentionops-connector/internal/scope"
)

const source = "11111111-1111-4111-8111-111111111111"

func configured(t *testing.T, schemas ...string) (*config.Config, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connector.yaml")
	if err := os.WriteFile(path, []byte("# the operator's file\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		ControlPlane: config.ControlPlane{
			URL: "https://connector.retentionops.example", PollWaitSeconds: 30, HeartbeatSeconds: 30,
		},
		Identity: config.Storage{Directory: "/var/lib/retentionops/identity"},
		State:    config.Storage{Directory: "/var/lib/retentionops/state"},
		Sources: map[string]*config.Source{
			source: {
				Type: "postgresql", Mode: config.SourceModeDiscoveryOnly,
				ConfiguredBy: config.ConfiguredByRetentionOps,
				Host:         "db.internal", Port: 5432, Database: "production",
				TLS: config.TLS{Mode: config.TLSVerifyFull},
				Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
					Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
				}},
				Safety: policy.Safety{
					AllowedSchemas: schemas, RequireApproval: true,
					Drift: policy.DriftPolicy{Mode: "strict"}, MaxDeleteRows: 1000, MaxBatchSize: 100,
					StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 300,
				},
			},
		},
	}, path
}

func TestTheChosenSchemasLandInTheOperatorsFile(t *testing.T) {
	configuration, path := configured(t)

	backup, err := scope.Set(path, configuration, source, []string{"billing", "public"},
		[]string{"audit", "billing", "public"})
	if err != nil {
		t.Fatal(err)
	}

	written := read(t, path)
	if !strings.Contains(written, "- billing") || !strings.Contains(written, "- public") {
		t.Fatalf("the choice is not in the file:\n%s", written)
	}
	// Never the ones nobody chose: the file is the boundary, and a schema that appears in it is
	// a schema this connector may enter.
	if strings.Contains(written, "- audit") {
		t.Fatalf("a schema nobody chose was allowed:\n%s", written)
	}
	if read(t, backup) != "# the operator's file\n" {
		t.Fatal("the previous file was not kept")
	}
}

func TestASchemaPostgreSQLWouldRefuseIsNotWritten(t *testing.T) {
	// An allow-list entry the database blocks anyway is a promise the connector cannot keep, and
	// the empty discovery that follows looks like a product fault rather than a missing grant.
	configuration, path := configured(t, "public")

	_, err := scope.Set(path, configuration, source, []string{"secret_admin"}, []string{"public"})
	if !errors.Is(err, scope.ErrOutsideGrants) {
		t.Fatalf("err = %v", err)
	}
	if read(t, path) != "# the operator's file\n" {
		t.Fatal("a refused choice still rewrote the file")
	}
}

func TestAnEmptyChoiceIsRefusedRatherThanSilentlyClearing(t *testing.T) {
	configuration, path := configured(t, "public")

	if _, err := scope.Set(path, configuration, source, nil, []string{"public"}); err == nil {
		t.Fatal("clearing the scope to nothing was accepted without a word")
	}
	if read(t, path) != "# the operator's file\n" {
		t.Fatal("the file changed")
	}
}

func TestASourceWithNoConfigurationYetHasNoScopeToChoose(t *testing.T) {
	configuration, path := configured(t)
	configuration.Sources[source].Host = ""
	configuration.Sources[source].Database = ""

	if _, err := scope.Set(path, configuration, source, []string{"public"}, []string{"public"}); err == nil {
		t.Fatal("a scope was chosen for a database nobody has described")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

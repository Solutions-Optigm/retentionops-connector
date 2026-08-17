package config_test

import (
	"strings"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
)

// The state between "the console sent an address" and "the operator chose the scope".
//
// It used to be refused, so every configuration the console sent came back REFUSED_INVALID: init
// had stopped asking for schemas, and nothing could fill them in until a connection worked — which
// required a configuration that validated. A deadlock produced by two correct changes.
func TestASourceTheConsoleConfiguredIsUsableBeforeItsScopeIsChosen(t *testing.T) {
	source := &config.Source{
		Type: "postgresql", Mode: config.SourceModeDiscoveryOnly,
		ConfiguredBy: config.ConfiguredByRetentionOps,
		Host:         "127.0.0.1", Port: 5432, Database: "production",
		TLS: config.TLS{Mode: config.TLSVerifyFull},
		Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
			Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
		}},
		Safety: policy.Safety{
			RequireApproval: true, Drift: policy.DriftPolicy{Mode: "strict"},
			MaxDeleteRows: 1000, MaxBatchSize: 100,
			StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 300,
		},
	}
	configuration := usable(source)

	if err := configuration.Validate(); err != nil {
		t.Fatalf("a configured source with no scope yet was refused: %v", err)
	}

	// Still refused where the file itself is the description: an empty list there is a policy
	// somebody wrote that can never do anything, not a step that has not happened yet.
	source.ConfiguredBy = config.ConfiguredByLocal
	err := configuration.Validate()
	if err == nil || !strings.Contains(err.Error(), "allowed_schemas is empty") {
		t.Fatalf("err = %v", err)
	}
}

func usable(source *config.Source) *config.Config {
	return &config.Config{
		ControlPlane: config.ControlPlane{
			URL: "https://connector.retentionops.example", PollWaitSeconds: 30, HeartbeatSeconds: 30,
		},
		Identity: config.Storage{Directory: "/var/lib/retentionops/identity"},
		State:    config.Storage{Directory: "/var/lib/retentionops/state"},
		Sources:  map[string]*config.Source{"11111111-1111-4111-8111-111111111111": source},
	}
}

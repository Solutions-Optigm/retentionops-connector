package sealedconfig

import (
	"errors"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
)

func configurationWithSource() *config.Config {
	return &config.Config{
		ControlPlane: config.ControlPlane{
			URL: "https://connector.retentionops.example", PollWaitSeconds: 30, HeartbeatSeconds: 30,
		},
		Identity: config.Storage{Directory: "/var/lib/retentionops/identity"},
		State:    config.Storage{Directory: "/var/lib/retentionops/state"},
		Sources: map[string]*config.Source{
			source: {
				Type: "postgresql", Mode: "discovery_only",
				Host: "old.internal", Port: 5432, Database: "old",
				TLS: config.TLS{Mode: "verify-full", CAFile: "/etc/retentionops/certs/postgres-ca.pem"},
				Reader: config.Credential{Username: "old_reader", Password: config.SecretRef{
					Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
				}},
				Safety: policy.Safety{
					AllowedSchemas: []string{"application"}, RequireApproval: true,
					Drift:         policy.DriftPolicy{Mode: "strict"},
					MaxDeleteRows: 1000, MaxBatchSize: 100,
					StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 300,
				},
			},
		},
	}
}

func TestApplyChangesTheConnectionAndNothingElse(t *testing.T) {
	configuration := configurationWithSource()
	before := configuration.Sources[source]
	safetyBefore := before.Safety
	modeBefore := before.Mode
	secretBefore := before.Reader.Password
	caBefore := before.TLS.CAFile

	err := Apply(configuration, source, SourceConfiguration{
		Host: "postgres.internal", Port: 6432, Database: "application",
		ReaderRole: "retentionops_reader", TLSMode: "verify-full",
	})
	if err != nil {
		t.Fatal(err)
	}

	after := configuration.Sources[source]
	if after.Host != "postgres.internal" || after.Port != 6432 || after.Database != "application" {
		t.Fatalf("the connection was not applied: %+v", after)
	}
	if after.Reader.Username != "retentionops_reader" {
		t.Fatalf("the reader role was not applied: %q", after.Reader.Username)
	}

	// The local safety policy is what the control plane may neither read nor widen. An envelope
	// that could reach it would be an envelope that decides what this connector may delete.
	if len(after.Safety.AllowedSchemas) != len(safetyBefore.AllowedSchemas) {
		t.Fatal("an envelope changed the local safety policy")
	}
	if after.Mode != modeBefore {
		t.Fatal("an envelope changed the execution mode")
	}
	if after.Reader.Password != secretBefore {
		t.Fatal("an envelope changed a secret reference")
	}
	if after.TLS.CAFile != caBefore {
		t.Fatal("an envelope changed the local CA path")
	}
}

// The console is the authority on which sources exist. A connector that created one because an
// envelope mentioned it would let the control plane add targets to a host by asserting them.
func TestApplyRefusesASourceThisConnectorDoesNotServe(t *testing.T) {
	configuration := configurationWithSource()
	err := Apply(configuration, "00000000-0000-4000-8000-000000000000", SourceConfiguration{
		Host: "postgres.internal", Port: 5432, Database: "application",
		ReaderRole: "retentionops_reader", TLSMode: "verify-full",
	})
	if !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("an unknown source was accepted: %v", err)
	}
}

// Authenticity says who wrote an envelope, never that what they wrote is runnable.
func TestApplyRefusesAnAuthenticatedButUnusableConfiguration(t *testing.T) {
	for name, broken := range map[string]SourceConfiguration{
		"an unknown TLS mode": {
			Host: "postgres.internal", Port: 5432, Database: "application",
			ReaderRole: "retentionops_reader", TLSMode: "trust-me",
		},
		"a role that is not an identifier": {
			Host: "postgres.internal", Port: 5432, Database: "application",
			ReaderRole: "Robert'); DROP TABLE students;--", TLSMode: "verify-full",
		},
	} {
		configuration := configurationWithSource()
		if err := Apply(configuration, source, broken); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestOutcomeCodesNeverCarryAMessage(t *testing.T) {
	for err, want := range map[error]string{
		nil:               OutcomeApplied,
		ErrExpired:        OutcomeRefusedExpired,
		ErrNotYetValid:    OutcomeRefusedExpired,
		ErrWrongRecipient: OutcomeRefusedUnreadable,
		ErrTooLarge:       OutcomeRefusedUnreadable,
		ErrVersion:        OutcomeRefusedUnreadable,
		ErrUnknownSource:  OutcomeRefusedInvalid,
	} {
		if got := OutcomeFor(err); got != want {
			t.Fatalf("OutcomeFor(%v) = %q, want %q", err, got, want)
		}
	}
}

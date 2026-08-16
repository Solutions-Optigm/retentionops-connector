package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/controlplane"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
	"github.com/solutions-optigm/retentionops-connector/internal/sealedconfig"
	"github.com/solutions-optigm/retentionops-connector/internal/telemetry"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

const (
	testOrganization = "11111111-1111-4111-8111-111111111111"
	testConnector    = "22222222-2222-4222-8222-222222222222"
	testSource       = "44444444-4444-4444-8444-444444444444"
)

// A whole connector, wired the way `run` wires one, against a control plane that redelivers.
func configuredAgent(t *testing.T, handler http.Handler) (*Agent, *identity.Identity, string) {
	t.Helper()
	controlPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, connectorPrivate, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := identity.Save(state, connectorPrivate, identity.Enrollment{
		ConnectorID: testConnector, OrganizationID: testOrganization,
		ControlPlanePublicKey: identity.EncodePublic(controlPublic), IssuedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(state)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := controlplane.New(server.URL, "", "test", id, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "connector.yaml")
	configuration := &config.Config{
		// The configuration must satisfy Validate, which insists on https. The client talks to the
		// test server; what the file declares is not what this test exercises.
		ControlPlane: config.ControlPlane{
			URL: "https://connector.retentionops.example", PollWaitSeconds: 30, HeartbeatSeconds: 30,
		},
		Identity: config.Storage{Directory: state},
		State:    config.Storage{Directory: state},
		Sources: map[string]*config.Source{
			testSource: {
				Type: "postgresql", Mode: "discovery_only",
				Host: "old.internal", Port: 5432, Database: "old",
				TLS: config.TLS{Mode: "verify-full", CAFile: "/etc/retentionops/certs/postgres-ca.pem"},
				Reader: config.Credential{Username: "old_reader", Password: config.SecretRef{
					Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
				}},
				Safety: policy.Safety{
					AllowedSchemas: []string{"application"}, RequireApproval: true,
					Drift: policy.DriftPolicy{Mode: "strict"}, MaxDeleteRows: 1000, MaxBatchSize: 100,
					StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 300,
				},
			},
		},
	}
	metrics := telemetry.NewMetrics()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	connector, err := New(configuration, id, client, secrets.Default(), metrics, log, "test", configPath)
	if err != nil {
		t.Fatal(err)
	}
	return connector, id, configPath
}

// The property the envelope id exists for: at-least-once delivery, applied exactly once.
func TestARedeliveredConfigurationIsAcknowledgedButNotReapplied(t *testing.T) {
	var mutex sync.Mutex
	var acknowledged []string

	var envelopeJSON []byte
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		switch {
		case strings.HasSuffix(request.URL.Path, "/configurations/pending"):
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"protocol_version":"1","configurations":[` + string(envelopeJSON) + `]}`))
		case strings.HasSuffix(request.URL.Path, "/ack"):
			body, _ := io.ReadAll(request.Body)
			var document map[string]string
			_ = json.Unmarshal(body, &document)
			acknowledged = append(acknowledged, document["outcome"])
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})

	connector, id, configPath := configuredAgent(t, handler)
	key, err := id.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sealed, err := sealedconfig.Seal(
		sealedconfig.SourceConfiguration{
			Host: "postgres.internal", Port: 6432, Database: "application",
			ReaderRole: "retentionops_reader", TLSMode: "verify-full",
		},
		key.PublicKey(),
		sealedconfig.Envelope{
			EnvelopeID: "b7c1d2e3-4f56-4789-a0b1-c2d3e4f56789", OrganizationID: testOrganization,
			SourceID: testSource, ConnectorID: testConnector,
			IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	envelopeJSON, err = json.Marshal(sealed)
	mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	connector.applyPendingConfigurations(context.Background())
	if got := connector.config.Sources[testSource]; got.Host != "postgres.internal" || got.Port != 6432 {
		t.Fatalf("the configuration was not applied: %+v", got)
	}
	written, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("the configuration was not persisted: %v", err)
	}
	if !strings.Contains(string(written), "postgres.internal") {
		t.Fatal("the persisted configuration does not carry the applied host")
	}

	// The same envelope again, as a lost acknowledgement produces.
	connector.config.Sources[testSource].Host = "tampered.internal"
	connector.applyPendingConfigurations(context.Background())
	if connector.config.Sources[testSource].Host != "tampered.internal" {
		t.Fatal("a redelivered envelope was applied a second time")
	}

	mutex.Lock()
	defer mutex.Unlock()
	if len(acknowledged) != 2 {
		t.Fatalf("acknowledgements = %v", acknowledged)
	}
	if acknowledged[0] != sealedconfig.OutcomeApplied {
		t.Fatalf("first outcome = %q", acknowledged[0])
	}
	if acknowledged[1] != sealedconfig.OutcomeAlreadyApplied {
		t.Fatalf("a redelivery reported %q instead of already-applied", acknowledged[1])
	}
}

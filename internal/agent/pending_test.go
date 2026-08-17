package agent

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/policy"
)

// A connector installed and enrolled before anybody said where its database is.
//
// This is the normal state for a minute or a day: the operator ran three commands on a server,
// and the console has not sent the configuration yet. What the connector says about it in the
// meantime is what the console's checklist believes.
func pendingAgent(t *testing.T, handler http.Handler) *Agent {
	t.Helper()
	connector, _, _ := configuredAgent(t, handler)
	connector.config.Sources[testSource] = &config.Source{
		Type: "postgresql", Mode: config.SourceModeDiscoveryOnly,
		ConfiguredBy: config.ConfiguredByRetentionOps,
		TLS:          config.TLS{Mode: config.TLSVerifyFull},
		Reader: config.Credential{Password: config.SecretRef{
			Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
		}},
		Safety: policy.Safety{
			AllowedSchemas: []string{"application"}, RequireApproval: true,
			Drift: policy.DriftPolicy{Mode: "strict"}, MaxDeleteRows: 1000, MaxBatchSize: 100,
			StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5, MaxDurationSeconds: 300,
		},
	}
	return connector
}

func TestAnUnconfiguredSourceIsReportedAsUnconfigured(t *testing.T) {
	// It used to report READY for anything the file declared, which was a claim nobody had
	// checked. The console ticked "connected to your database" over a connector that had never
	// been told which database.
	var mutex sync.Mutex
	var heartbeat map[string]any
	connector := pendingAgent(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/heartbeat") {
			mutex.Lock()
			_ = json.NewDecoder(request.Body).Decode(&heartbeat)
			mutex.Unlock()
		}
		writer.WriteHeader(http.StatusNoContent)
	}))

	connector.sendHeartbeat(t.Context())

	mutex.Lock()
	defer mutex.Unlock()
	sources, _ := heartbeat["sources"].([]any)
	if len(sources) != 1 {
		t.Fatalf("sources = %v", heartbeat["sources"])
	}
	reported, _ := sources[0].(map[string]any)
	if reported["status"] != "UNCONFIGURED" {
		t.Fatalf("status = %v, want UNCONFIGURED", reported["status"])
	}
	// A TLS mode for a connection that cannot be made yet is a fact about nothing.
	if _, present := reported["tls_mode"]; present {
		t.Fatalf("an unconfigured source reported a transport mode: %v", reported)
	}
}

package doctor

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
)

func TestControlPlaneCheckUsesTheConfiguredPrivateAuthority(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	authority := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	path := filepath.Join(t.TempDir(), "control-plane-ca.pem")
	if err := os.WriteFile(path, authority, 0o600); err != nil {
		t.Fatal(err)
	}

	report := &Report{}
	checkControlPlane(t.Context(), report, &config.Config{
		ControlPlane: config.ControlPlane{URL: server.URL, CAFile: path},
	})

	if len(report.Checks) != 2 {
		t.Fatalf("expected DNS and HTTPS checks, got %+v", report.Checks)
	}
	if got := report.Checks[1]; got.Name != "Control plane HTTPS" || got.Outcome != Pass {
		t.Fatalf("configured private authority was ignored: %+v", got)
	}
}

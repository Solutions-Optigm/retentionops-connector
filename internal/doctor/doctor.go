// Package doctor answers "why isn't this working" without anyone having to read a log.
//
// It is the first thing an operator runs and the first thing support asks for. Every check names
// exactly one thing that can be wrong, in the order a packet would encounter it, so the first
// FAIL is the thing to fix.
package doctor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

// Outcome is the result of one check.
type Outcome string

// Check outcomes.
const (
	Pass Outcome = "PASS"
	Warn Outcome = "WARN"
	Fail Outcome = "FAIL"
	Skip Outcome = "SKIP"
)

// Check is one line of the report.
type Check struct {
	Name    string
	Outcome Outcome
	Detail  string
}

// Report is the whole run.
type Report struct {
	Checks []Check
}

func (r *Report) add(name string, outcome Outcome, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, Outcome: outcome, Detail: fmt.Sprintf(format, args...)})
}

// Healthy reports whether nothing failed. Warnings do not make a connector unhealthy: a source
// configured for inspection only legitimately has no executor to validate.
func (r *Report) Healthy() bool {
	for _, check := range r.Checks {
		if check.Outcome == Fail {
			return false
		}
	}
	return true
}

// Write renders the report as aligned text.
func (r *Report) Write(out io.Writer) {
	width := 0
	for _, check := range r.Checks {
		if len(check.Name) > width {
			width = len(check.Name)
		}
	}
	for _, check := range r.Checks {
		fmt.Fprintf(out, "%-*s  %-4s  %s\n", width, check.Name, check.Outcome, check.Detail)
	}
}

// Run executes every check.
//
// It deliberately takes the same code paths the running connector does — the same config loader,
// the same secret providers, the same TLS settings — because a doctor that proves a *different*
// path works is worse than no doctor at all.
func Run(ctx context.Context, configuration *config.Config, id *identity.Identity, registry *secrets.Registry) *Report {
	report := &Report{}
	report.add("Configuration", Pass, "%d source(s) declared", len(configuration.Sources))

	if digest, err := configuration.PolicyDigest(); err != nil {
		report.add("Local policy", Fail, "%v", err)
	} else {
		report.add("Local policy", Pass, "%s", digest)
	}

	checkIdentity(report, configuration, id)
	checkControlPlane(ctx, report, configuration)

	for sourceID, source := range configuration.Sources {
		checkSource(ctx, report, sourceID, source, registry)
	}
	return report
}

func checkIdentity(report *Report, configuration *config.Config, id *identity.Identity) {
	if err := config.RequireDirectoryIsPrivate(configuration.Identity.Directory); err != nil {
		report.add("Identity storage", Fail, "%v", err)
	} else {
		report.add("Identity storage", Pass, "%s", configuration.Identity.Directory)
	}
	if id == nil {
		report.add("Connector identity", Fail, "not enrolled; run `retentionops-connector enroll`")
		return
	}
	report.add("Connector identity", Pass, "connector %s in organization %s", id.ConnectorID, id.OrganizationID)
	report.add("Pinned control-plane key", Pass, "%s", identity.Fingerprint(id.ControlPlaneKey()))
}

func checkControlPlane(ctx context.Context, report *Report, configuration *config.Config) {
	parsed, err := url.Parse(configuration.ControlPlane.URL)
	if err != nil {
		report.add("Control plane URL", Fail, "%v", err)
		return
	}
	host := parsed.Hostname()
	if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
		report.add("Control plane DNS", Fail, "%s does not resolve: %v", host, err)
		return
	}
	report.add("Control plane DNS", Pass, "%s", host)

	// A HEAD to the root proves TLS and reachability without asserting anything about the API
	// surface. Any HTTP status at all means the handshake completed, which is the question.
	client := &http.Client{Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, configuration.ControlPlane.URL, nil)
	if err != nil {
		report.add("Control plane HTTPS", Fail, "%v", err)
		return
	}
	response, err := client.Do(request)
	if err != nil {
		report.add("Control plane HTTPS", Fail, "%v", err)
		return
	}
	defer response.Body.Close()
	report.add("Control plane HTTPS", Pass, "TLS established, HTTP %d", response.StatusCode)
}

func checkSource(ctx context.Context, report *Report, id string, source *config.Source, registry *secrets.Registry) {
	label := "Source " + id[:8]

	address := net.JoinHostPort(source.Host, strconv.Itoa(source.Port))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		report.add(label+" TCP", Fail, "%s unreachable: %v", address, err)
		return
	}
	_ = connection.Close()
	report.add(label+" TCP", Pass, "%s", address)

	for role, credential := range map[string]config.Credential{
		"reader":   source.Reader,
		"executor": source.Executor,
	} {
		if role == "executor" && !source.Safety.GrantsDelete() {
			report.add(label+" executor secret", Skip, "no table grants delete")
			continue
		}
		if !registry.Supports(credential.Password.Provider) {
			report.add(label+" "+role+" secret", Fail, "unknown provider %q", credential.Password.Provider)
			continue
		}
		if _, err := registry.Resolve(ctx, credential.Password.Provider, credential.Password.Ref); err != nil {
			report.add(label+" "+role+" secret", Fail, "%v", err)
			continue
		}
		// The value is discarded immediately. What is being proved is that it resolves, not
		// what it is — the doctor never prints or retains a credential.
		report.add(label+" "+role+" secret", Pass, "resolved through %s", credential.Password.Provider)
	}

	adapter := postgres.New(id, source, registry, discardLogger())
	statistics, err := adapter.TestConnection(ctx)
	if err != nil {
		report.add(label+" PostgreSQL", Fail, "%s", postgres.Classify(err))
		return
	}
	report.add(label+" PostgreSQL", Pass, "server %s, tls %s", statistics.DatabaseVersion, source.TLS.Mode)
	if source.Safety.GrantsDelete() && !statistics.ExecutorValidated {
		report.add(label+" executor identity", Warn, "the executor could not connect; deletes would fail")
	}
}

// discardLogger keeps the adapter's own diagnostics out of the report. The doctor's output is a
// tidy, aligned table an operator can read at a glance; interleaving structured JSON logs into it
// would defeat the point.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

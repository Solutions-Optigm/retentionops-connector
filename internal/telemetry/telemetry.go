// Package telemetry is local-only observability.
//
// Nothing here is shipped to RetentionOps. The connector's logs and metrics stay on the
// customer's host, exposed on a listener they choose, scraped by their own Prometheus. The
// control plane learns only what the protocol carries, which is counts and status codes.
package telemetry

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// forbiddenKeys never appear in a log line, whatever a caller passes.
//
// A redaction list is a weak control on its own — the strong control is that the connector has
// no code path that puts a password or a row value into a log call. This exists because "no code
// path today" is not the same as "no code path after the next contribution".
var forbiddenKeys = []string{"password", "secret", "token", "credential", "dsn", "row", "value", "key"}

// NewLogger builds the process logger.
func NewLogger(format, level string) *slog.Logger {
	options := &slog.HandlerOptions{
		Level:       parseLevel(level),
		ReplaceAttr: redact,
	}
	var handler slog.Handler = slog.NewJSONHandler(os.Stderr, options)
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, options)
	}
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func redact(groups []string, attr slog.Attr) slog.Attr {
	_ = groups
	lowered := strings.ToLower(attr.Key)
	for _, forbidden := range forbiddenKeys {
		if strings.Contains(lowered, forbidden) {
			// The key is kept so the shape of the log line stays stable and the omission is
			// visible; only the value is destroyed.
			return slog.String(attr.Key, "[redacted]")
		}
	}
	return attr
}

// Metrics is a small Prometheus-compatible registry.
//
// Hand-rolled rather than pulling in a client library: this connector holds delete rights on a
// production database, and every dependency it carries is one the customer's security team has
// to review. Counters and gauges with labels are the whole requirement, and they are 100 lines.
type Metrics struct {
	mutex   sync.Mutex
	help    map[string]string
	kinds   map[string]string
	samples map[string]map[string]float64
}

// NewMetrics builds the registry with the connector's metric definitions.
func NewMetrics() *Metrics {
	metrics := &Metrics{
		help:    make(map[string]string),
		kinds:   make(map[string]string),
		samples: make(map[string]map[string]float64),
	}
	metrics.define("retentionops_connector_up", "gauge", "1 when the connector is running.")
	metrics.define("retentionops_connector_jobs_total", "counter", "Jobs finished, by operation and status.")
	metrics.define("retentionops_connector_denials_total", "counter", "Jobs refused, by stable denial code.")
	metrics.define("retentionops_connector_rows_deleted_total", "counter", "Rows deleted, by data source.")
	metrics.define("retentionops_connector_batches_total", "counter", "Committed delete batches, by data source.")
	metrics.define("retentionops_connector_control_plane_requests_total", "counter", "Control-plane calls, by outcome.")
	metrics.define("retentionops_connector_last_heartbeat_seconds", "gauge", "Unix time of the last accepted heartbeat.")
	metrics.Set("retentionops_connector_up", nil, 1)
	return metrics
}

func (m *Metrics) define(name, kind, help string) {
	m.kinds[name] = kind
	m.help[name] = help
	m.samples[name] = make(map[string]float64)
}

// Inc adds one to a counter.
func (m *Metrics) Inc(name string, labels map[string]string) { m.Add(name, labels, 1) }

// Add increases a counter by delta.
func (m *Metrics) Add(name string, labels map[string]string, delta float64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if series, ok := m.samples[name]; ok {
		series[encodeLabels(labels)] += delta
	}
}

// Set writes a gauge.
func (m *Metrics) Set(name string, labels map[string]string, value float64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if series, ok := m.samples[name]; ok {
		series[encodeLabels(labels)] = value
	}
}

// Touch records "this happened now" on a timestamp gauge.
func (m *Metrics) Touch(name string) {
	m.Set(name, nil, float64(time.Now().Unix()))
}

// ServeHTTP renders the Prometheus text exposition format.
func (m *Metrics) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	names := make([]string, 0, len(m.samples))
	for name := range m.samples {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s %s\n", name, m.help[name], name, m.kinds[name])
		series := make([]string, 0, len(m.samples[name]))
		for labels := range m.samples[name] {
			series = append(series, labels)
		}
		sort.Strings(series)
		for _, labels := range series {
			fmt.Fprintf(writer, "%s%s %g\n", name, labels, m.samples[name][labels])
		}
	}
}

// Listen exposes the registry, if an address is configured.
//
// Returns the server so the caller owns its shutdown. An empty address disables the listener
// entirely: a connector in a network where nothing scrapes it should open no socket at all.
func Listen(address string, metrics *Metrics, log *slog.Logger) *http.Server {
	if address == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics listener stopped", "error", err)
		}
	}()
	log.Info("metrics listener started", "address", address)
	return server
}

func encodeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%q", key, labels[key]))
	}
	return "{" + strings.Join(pairs, ",") + "}"
}

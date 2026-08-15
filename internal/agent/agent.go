// Package agent is the run loop: poll, verify, authorize, execute, report.
//
// One job runs at a time. A connector holding delete rights on a production database is not the
// place to discover a concurrency bug, and retention work is not latency-sensitive — the whole
// point of the design is that it happens on a schedule, under an approval, with ceilings.
package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/controlplane"
	"github.com/solutions-optigm/retentionops-connector/internal/evidence"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/internal/jobs"
	"github.com/solutions-optigm/retentionops-connector/internal/telemetry"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

// nonceRetention must exceed the longest job lifetime the control plane issues, so a replayed
// job is still recognised long after it stopped being executable.
const nonceRetention = 48 * time.Hour

// Agent is one running connector.
type Agent struct {
	config       *config.Config
	identity     *identity.Identity
	client       *controlplane.Client
	verifier     *jobs.Verifier
	ledger       *jobs.ReplayLedger
	builder      *evidence.Builder
	secrets      *secrets.Registry
	metrics      *telemetry.Metrics
	log          *slog.Logger
	version      string
	control      func(context.Context, string) (*protocolv1.ExecutionControl, error)
	event        func(context.Context, protocolv1.JobEvent) error
	controlRetry time.Duration
}

// New assembles a connector from an already-validated configuration and an enrolled identity.
func New(
	configuration *config.Config,
	id *identity.Identity,
	client *controlplane.Client,
	registry *secrets.Registry,
	metrics *telemetry.Metrics,
	log *slog.Logger,
	version string,
) (*Agent, error) {
	ledger, err := jobs.NewReplayLedger(config.NoncesDirectory(configuration.State.Directory), nonceRetention)
	if err != nil {
		return nil, err
	}
	policyDigest, err := configuration.PolicyDigest()
	if err != nil {
		return nil, err
	}
	return &Agent{
		config:   configuration,
		identity: id,
		client:   client,
		verifier: jobs.NewVerifier(id, ledger),
		ledger:   ledger,
		builder: &evidence.Builder{
			OrganizationID: id.OrganizationID,
			ConnectorID:    id.ConnectorID,
			Version:        version,
			PolicyDigest:   policyDigest,
		},
		secrets:      registry,
		metrics:      metrics,
		log:          log,
		version:      version,
		control:      client.Control,
		event:        client.Event,
		controlRetry: time.Second,
	}, nil
}

// Run polls until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("connector started",
		"connector_id", a.identity.ConnectorID,
		"organization_id", a.identity.OrganizationID,
		"policy_digest", a.builder.PolicyDigest,
		"sources", len(a.config.Sources),
		"control_plane_key", identity.Fingerprint(a.identity.ControlPlaneKey()))

	go a.heartbeatLoop(ctx)
	go a.pruneLoop(ctx)

	wait := time.Duration(a.config.ControlPlane.PollWaitSeconds) * time.Second
	failures := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := a.client.NextJob(ctx, wait)
		switch {
		case errors.Is(err, controlplane.ErrNoWork):
			a.metrics.Inc("retentionops_connector_control_plane_requests_total", map[string]string{"outcome": "idle"})
			failures = 0
			continue
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures++
			a.metrics.Inc("retentionops_connector_control_plane_requests_total", map[string]string{"outcome": "error"})
			a.log.Warn("poll failed", "error", err, "consecutive_failures", failures)
			if !sleep(ctx, backoff(failures)) {
				return ctx.Err()
			}
			continue
		}
		failures = 0
		a.metrics.Inc("retentionops_connector_control_plane_requests_total", map[string]string{"outcome": "job"})
		a.handle(ctx, raw)
	}
}

// backoff grows to a one-minute ceiling with jitter.
//
// Jitter matters more than the curve: without it, every connector belonging to every customer
// reconnects in lockstep after a control-plane restart and turns a recovery into a second
// outage.
func backoff(failures int) time.Duration {
	seconds := 1 << min(failures, 6)
	capped := min(time.Duration(seconds)*time.Second, time.Minute)
	return capped/2 + time.Duration(rand.Int64N(int64(capped/2)+1))
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// handle takes one job all the way to a signed result.
//
// Every exit from this function reports something. A job that is silently dropped leaves the
// control plane unable to distinguish "your connector refused" from "your connector is gone",
// and those need very different responses from an operator.
func (a *Agent) handle(ctx context.Context, raw []byte) {
	startedAt := time.Now()

	job, err := a.verifier.Verify(raw)
	if err != nil {
		refusal, ok := jobs.AsRefusal(err)
		if !ok || job == nil {
			// Unparseable, or a ledger failure: there is no job identifier to report against.
			a.log.Error("a document that is not a v1 job was received", "error", err)
			return
		}
		a.log.Warn("job refused during verification",
			"job_id", job.JobID, "code", refusal.Code, "reason", refusal.Reason)
		a.report(ctx, job, func() (protocolv1.JobResult, error) {
			return a.builder.Refusal(job, refusal.Code, startedAt, a.identity)
		})
		a.metrics.Inc("retentionops_connector_denials_total", map[string]string{"code": string(refusal.Code)})
		return
	}

	if err := a.client.Acknowledge(ctx, job.JobID); err != nil {
		// Not fatal: the work is authorized and the result will arrive regardless. The control
		// plane treats a missing ack as "still dispatched", never as "completed".
		a.log.Warn("acknowledgement failed", "job_id", job.JobID, "error", err)
	}

	source, known := a.config.Source(job.DataSourceID)
	if !known {
		a.log.Warn("job names a data source this connector was never given",
			"job_id", job.JobID, "data_source_id", job.DataSourceID)
		a.report(ctx, job, func() (protocolv1.JobResult, error) {
			return a.builder.Refusal(job, protocolv1.DeniedUnknownSource, startedAt, a.identity)
		})
		a.metrics.Inc("retentionops_connector_denials_total", map[string]string{"code": string(protocolv1.DeniedUnknownSource)})
		return
	}
	if job.Operation == protocolv1.OpDelete && source.Mode == config.SourceModeDiscoveryOnly {
		// EXECUTION_DISABLED is deliberately local detail. The wire protocol keeps its reviewed
		// v1 denial vocabulary and carries DENIED_BY_LOCAL_POLICY rather than growing a fifth
		// remotely addressable capability for an installation concern.
		a.log.Warn("job refused because local execution is disabled",
			"job_id", job.JobID, "operation", job.Operation, "reason_code", config.ExecutionDisabledCode)
		a.report(ctx, job, func() (protocolv1.JobResult, error) {
			return a.builder.Refusal(job, protocolv1.DeniedByLocalPolicy, startedAt, a.identity)
		})
		a.metrics.Inc("retentionops_connector_denials_total", map[string]string{"code": string(protocolv1.DeniedByLocalPolicy)})
		return
	}

	decision := source.Safety.Authorize(job, time.Now())
	if !decision.Allowed {
		a.log.Warn("job refused by the local safety policy",
			"job_id", job.JobID, "operation", job.Operation, "code", decision.Code, "reason", decision.Reason)
		a.report(ctx, job, func() (protocolv1.JobResult, error) {
			return a.builder.Refusal(job, decision.Code, startedAt, a.identity)
		})
		a.metrics.Inc("retentionops_connector_denials_total", map[string]string{"code": string(decision.Code)})
		return
	}

	a.execute(ctx, job, source, decision.Effective, startedAt)
}

func (a *Agent) execute(
	ctx context.Context,
	job *protocolv1.JobEnvelope,
	source *config.Source,
	limits protocolv1.Limits,
	startedAt time.Time,
) {
	adapter := postgres.New(job.DataSourceID, source, a.secrets, a.log)

	statistics, complete, err := a.run(ctx, adapter, job, limits)
	if err != nil {
		var cancelled *controlCancelledError
		if errors.As(err, &cancelled) {
			a.log.Info("job cancelled at a checkpoint", "job_id", job.JobID, "rows_deleted", statisticsRows(statistics))
			a.report(ctx, job, func() (protocolv1.JobResult, error) {
				return a.builder.Cancelled(job, statistics, startedAt, a.identity)
			})
			a.finish(job, "CANCELLED")
			return
		}
		var stale *staleError
		if errors.As(err, &stale) {
			a.log.Warn("plan is stale", "job_id", job.JobID, "observed_rows", stale.observed)
			a.report(ctx, job, func() (protocolv1.JobResult, error) {
				return a.builder.Stale(job, stale.observed, startedAt, a.identity)
			})
			a.finish(job, "PLAN_STALE")
			return
		}
		code := postgres.Classify(err)
		a.log.Error("job failed", "job_id", job.JobID, "operation", job.Operation, "code", code, "error", err)
		a.report(ctx, job, func() (protocolv1.JobResult, error) {
			return a.builder.Failure(job, code, startedAt, a.identity)
		})
		a.finish(job, "FAILED")
		return
	}

	a.report(ctx, job, func() (protocolv1.JobResult, error) {
		return a.builder.Success(job, statistics, complete, startedAt, a.identity)
	})
	if statistics != nil && statistics.RowsDeleted > 0 {
		labels := map[string]string{"data_source_id": job.DataSourceID}
		a.metrics.Add("retentionops_connector_rows_deleted_total", labels, float64(statistics.RowsDeleted))
		a.metrics.Add("retentionops_connector_batches_total", labels, float64(statistics.Batches))
	}
	status := "COMPLETED"
	if !complete {
		status = "PARTIAL"
	}
	a.finish(job, status)
}

type staleError struct{ observed int64 }

func (e *staleError) Error() string { return "plan is stale" }

type controlCancelledError struct{}

func (e *controlCancelledError) Error() string { return "job cancelled at a checkpoint" }

func (a *Agent) run(
	ctx context.Context,
	adapter *postgres.Adapter,
	job *protocolv1.JobEnvelope,
	limits protocolv1.Limits,
) (*protocolv1.Statistics, bool, error) {
	switch job.Operation {
	case protocolv1.OpTestConnection:
		statistics, err := adapter.TestConnection(ctx)
		return statistics, true, err
	case protocolv1.OpDiscover:
		statistics, err := adapter.Discover(ctx)
		return statistics, true, err
	case protocolv1.OpCount:
		statistics, err := adapter.Count(ctx, *job.Target, *job.Predicate, job.Condition, job.Holds, limits)
		return statistics, true, err
	case protocolv1.OpDelete:
		return a.delete(ctx, adapter, job, limits)
	default:
		return nil, false, errors.New("agent: unreachable operation")
	}
}

// delete recounts before it removes anything.
//
// The count runs as the reader; only then does the executor secret get resolved. Between the
// plan a human approved and this moment the table has kept living, so the recount is what turns
// "approved to delete 24 391 rows" into a statement that is still true — or into PLAN_STALE.
func (a *Agent) delete(
	ctx context.Context,
	adapter *postgres.Adapter,
	job *protocolv1.JobEnvelope,
	limits protocolv1.Limits,
) (*protocolv1.Statistics, bool, error) {
	measured, err := adapter.Count(ctx, *job.Target, *job.Predicate, job.Condition, job.Holds, limits)
	if err != nil {
		return nil, false, err
	}
	if evidence.DriftExceeded(job.Drift, measured.CandidateRows) {
		return nil, false, &staleError{observed: measured.CandidateRows}
	}

	sequence := 0
	a.emit(ctx, job, protocolv1.EventAccepted, sequence, 0, 0, 0)
	controlVersion := int64(0)
	if err := a.awaitControl(ctx, job, &sequence, &controlVersion, 0); err != nil {
		return &protocolv1.Statistics{
			ObservedRows:    measured.CandidateRows,
			CandidateRows:   measured.CandidateRows,
			ResourceRows:    measured.ResourceRows,
			BlockedHoldRows: measured.BlockedHoldRows,
			EstimatedBytes:  measured.EstimatedBytes,
			Oldest:          measured.Oldest,
			Newest:          measured.Newest,
		}, false, err
	}

	observer := func(affected, cumulative int64, elapsed time.Duration) error {
		sequence++
		a.emit(ctx, job, protocolv1.EventBatchCommitted, sequence, affected, cumulative, elapsed)
		return a.awaitControl(ctx, job, &sequence, &controlVersion, cumulative)
	}
	statistics, complete, err := adapter.Delete(ctx, *job.Target, *job.Predicate, job.Condition, job.Holds, limits, observer)
	if statistics != nil {
		statistics.ObservedRows = measured.CandidateRows
		statistics.CandidateRows = measured.CandidateRows
		statistics.ResourceRows = measured.ResourceRows
		statistics.BlockedHoldRows = measured.BlockedHoldRows
		statistics.EstimatedBytes = measured.EstimatedBytes
		statistics.Oldest = measured.Oldest
		statistics.Newest = measured.Newest
		// Reaching the approved ceiling is complete when the pre-delete recount proved that
		// the ceiling is exactly the whole candidate set. Running one more DELETE merely to
		// observe zero rows would turn a successful bounded job into a false PARTIAL result.
		if statistics.RowsDeleted >= measured.CandidateRows {
			complete = true
		}
	}
	if err != nil {
		// A batched delete that fails mid-run has still committed everything it reported. The
		// events already delivered are the record of that, and the failure below names the class.
		a.emit(ctx, job, protocolv1.EventAborted, sequence+1, 0, statisticsRows(statistics), 0)
		return statistics, false, err
	}
	return statistics, complete, nil
}

// awaitControl is the destructive checkpoint gate.
//
// An unavailable or invalid control answer pauses locally and is retried; it never degrades to
// RUN. The immutable JobEnvelope still defines what may happen, while this short-lived signed
// decision answers only whether another already-approved batch may begin now.
func (a *Agent) awaitControl(
	ctx context.Context,
	job *protocolv1.JobEnvelope,
	sequence *int,
	highestVersion *int64,
	cumulative int64,
) error {
	paused := false
	for {
		control, err := a.control(ctx, job.JobID)
		if err != nil {
			a.log.Warn("checkpoint control unavailable; remaining paused locally", "job_id", job.JobID, "error", err)
			if !sleep(ctx, a.controlRetry) {
				return ctx.Err()
			}
			continue
		}
		if control.ExecutionVersion < *highestVersion {
			a.log.Warn("stale checkpoint control refused", "job_id", job.JobID, "execution_version", control.ExecutionVersion)
			if !sleep(ctx, a.controlRetry) {
				return ctx.Err()
			}
			continue
		}
		*highestVersion = control.ExecutionVersion
		switch control.Action {
		case protocolv1.ControlRun:
			if paused {
				*sequence++
				a.emit(ctx, job, protocolv1.EventResumed, *sequence, 0, cumulative, 0)
			}
			return nil
		case protocolv1.ControlCancel:
			return &controlCancelledError{}
		case protocolv1.ControlPause:
			if !paused {
				paused = true
				*sequence++
			}
			// Re-send the same idempotent PAUSED event until the server acknowledges it. The
			// event is what advances PAUSING to PAUSED; losing its first delivery must not
			// leave the console claiming that a pause is still merely requested.
			a.emit(ctx, job, protocolv1.EventPaused, *sequence, 0, cumulative, 0)
			if !sleep(ctx, a.controlRetry) {
				return ctx.Err()
			}
		}
	}
}

func statisticsRows(statistics *protocolv1.Statistics) int64 {
	if statistics == nil {
		return 0
	}
	return statistics.RowsDeleted
}

func (a *Agent) emit(
	ctx context.Context,
	job *protocolv1.JobEnvelope,
	eventType string,
	sequence int,
	affected, cumulative int64,
	elapsed time.Duration,
) {
	event := protocolv1.JobEvent{
		ProtocolVersion: protocolv1.Version,
		JobID:           job.JobID,
		OrganizationID:  a.identity.OrganizationID,
		ConnectorID:     a.identity.ConnectorID,
		Sequence:        sequence,
		EventType:       eventType,
		OccurredAt:      time.Now().UTC(),
		AffectedRows:    affected,
		CumulativeRows:  cumulative,
		DurationMS:      elapsed.Milliseconds(),
	}
	// Progress delivery is best-effort by design: failing to report a committed batch must never
	// abort a job that is otherwise succeeding. The signed result at the end is the record of
	// truth; events are what make the console useful while the job is still running.
	if err := a.event(ctx, event); err != nil {
		a.log.Debug("event delivery failed", "job_id", job.JobID, "sequence", sequence, "error", err)
	}
}

// report delivers a signed result, retrying briefly.
//
// The result is the only durable trace the control plane will have of what happened. Losing it
// because of one failed request would leave a job that really ran looking like a job that never
// did, so this retries past a short network interruption before giving up.
func (a *Agent) report(ctx context.Context, job *protocolv1.JobEnvelope, build func() (protocolv1.JobResult, error)) {
	result, err := build()
	if err != nil {
		a.log.Error("could not seal a result", "job_id", job.JobID, "error", err)
		return
	}
	for attempt := 1; attempt <= 5; attempt++ {
		if err := a.client.Complete(ctx, result); err == nil {
			return
		} else if ctx.Err() != nil {
			return
		} else {
			a.log.Warn("result delivery failed", "job_id", job.JobID, "attempt", attempt, "error", err)
		}
		if !sleep(ctx, backoff(attempt)) {
			return
		}
	}
	a.log.Error("result could not be delivered; it is recorded here only",
		"job_id", job.JobID, "status", result.Status, "result_digest", result.ResultDigest)
}

func (a *Agent) finish(job *protocolv1.JobEnvelope, status string) {
	a.metrics.Inc("retentionops_connector_jobs_total", map[string]string{
		"operation": string(job.Operation),
		"status":    status,
	})
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(a.config.ControlPlane.HeartbeatSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		a.sendHeartbeat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	sources := make([]protocolv1.SourceStatus, 0, len(a.config.Sources))
	for id, source := range a.config.Sources {
		sources = append(sources, protocolv1.SourceStatus{
			DataSourceID:  id,
			Type:          source.Type,
			Status:        protocolv1.SourceReady,
			TLSMode:       source.TLS.Mode,
			AllowedTables: source.Safety.AllowedTableCount(),
		})
	}
	heartbeat := protocolv1.Heartbeat{
		ProtocolVersion:  protocolv1.Version,
		OrganizationID:   a.identity.OrganizationID,
		ConnectorID:      a.identity.ConnectorID,
		ConnectorVersion: a.version,
		OccurredAt:       time.Now().UTC(),
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		Capabilities:     protocolv1.Operations,
		PolicyDigest:     a.builder.PolicyDigest,
		Sources:          sources,
	}
	if err := a.client.Heartbeat(ctx, heartbeat); err != nil {
		a.log.Warn("heartbeat failed", "error", err)
		return
	}
	a.metrics.Touch("retentionops_connector_last_heartbeat_seconds")
}

// pruneLoop keeps the replay ledger from growing without bound.
func (a *Agent) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if removed, err := a.ledger.Prune(time.Now()); err != nil {
				a.log.Warn("could not prune the replay ledger", "error", err)
			} else if removed > 0 {
				a.log.Debug("pruned expired nonces", "removed", removed)
			}
		}
	}
}

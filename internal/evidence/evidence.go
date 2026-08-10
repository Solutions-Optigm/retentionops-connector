// Package evidence builds the signed record a connector returns for every job, including the
// ones it refused.
//
// A refusal is evidence too. "RetentionOps asked to delete from a table you never allow-listed,
// and your connector said no, at 14:02, under policy digest sha256:…" is exactly the record a
// customer needs and exactly the record a compromised control plane would prefer not to exist —
// which is why it is signed by the connector's own key rather than recorded by us.
package evidence

import (
	"time"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// Builder assembles results for one connector.
type Builder struct {
	OrganizationID string
	ConnectorID    string
	Version        string
	PolicyDigest   string
}

// Refusal builds a signed DENIED result.
//
// The stable code travels; the human-readable reason does not. An operator reading the console
// sees DENIED_TARGET_NOT_ALLOWED and goes to their own connector logs for the detail, which is
// the only place the detail belongs.
func (b *Builder) Refusal(
	job *protocolv1.JobEnvelope,
	code protocolv1.DenialCode,
	startedAt time.Time,
	signer protocolv1.Signer,
) (protocolv1.JobResult, error) {
	result := b.base(job, protocolv1.StatusDenied, startedAt)
	result.DenialCode = code
	return b.seal(result, signer)
}

// Failure builds a signed FAILED result.
func (b *Builder) Failure(
	job *protocolv1.JobEnvelope,
	code protocolv1.FailureCode,
	startedAt time.Time,
	signer protocolv1.Signer,
) (protocolv1.JobResult, error) {
	result := b.base(job, protocolv1.StatusFailed, startedAt)
	result.FailureCode = code
	return b.seal(result, signer)
}

// Stale builds a signed PLAN_STALE result, carrying the recount that caused it.
//
// The observed count is included on purpose: the control plane has to be able to re-plan without
// asking again, and the number is an aggregate, not data.
func (b *Builder) Stale(
	job *protocolv1.JobEnvelope,
	observed int64,
	startedAt time.Time,
	signer protocolv1.Signer,
) (protocolv1.JobResult, error) {
	result := b.base(job, protocolv1.StatusPlanStale, startedAt)
	result.Statistics = &protocolv1.Statistics{ObservedRows: observed}
	return b.seal(result, signer)
}

// Success builds a signed COMPLETED or PARTIAL result.
func (b *Builder) Success(
	job *protocolv1.JobEnvelope,
	statistics *protocolv1.Statistics,
	complete bool,
	startedAt time.Time,
	signer protocolv1.Signer,
) (protocolv1.JobResult, error) {
	status := protocolv1.StatusPartial
	if complete {
		status = protocolv1.StatusCompleted
	}
	result := b.base(job, status, startedAt)
	result.Statistics = statistics
	return b.seal(result, signer)
}

// Cancelled builds the signed record for batches committed before a checkpoint cancellation.
func (b *Builder) Cancelled(
	job *protocolv1.JobEnvelope,
	statistics *protocolv1.Statistics,
	startedAt time.Time,
	signer protocolv1.Signer,
) (protocolv1.JobResult, error) {
	result := b.base(job, protocolv1.StatusCancelled, startedAt)
	result.Statistics = statistics
	return b.seal(result, signer)
}

func (b *Builder) base(job *protocolv1.JobEnvelope, status protocolv1.Status, startedAt time.Time) protocolv1.JobResult {
	result := protocolv1.JobResult{
		ProtocolVersion:  protocolv1.Version,
		JobID:            job.JobID,
		OrganizationID:   b.OrganizationID,
		ConnectorID:      b.ConnectorID,
		DataSourceID:     job.DataSourceID,
		Operation:        job.Operation,
		Status:           status,
		StartedAt:        startedAt.UTC(),
		CompletedAt:      time.Now().UTC(),
		ConnectorVersion: b.Version,
		PlanDigest:       job.PlanDigest,
		PolicyDigest:     b.PolicyDigest,
	}
	if job.Approval != nil {
		result.ApprovalID = job.Approval.ID
	}
	return result
}

func (b *Builder) seal(result protocolv1.JobResult, signer protocolv1.Signer) (protocolv1.JobResult, error) {
	if err := result.Seal(signer); err != nil {
		return protocolv1.JobResult{}, err
	}
	return result, nil
}

// DriftExceeded reports whether a recount has moved too far from what the plan measured.
//
// Both tolerances have to be satisfied when both are configured, and the absence of any
// tolerance means any change at all is too much. A plan approved against 24 391 rows is an
// approval of that operation, not of whatever the table happens to hold when the job runs.
func DriftExceeded(drift *protocolv1.Drift, observed int64) bool {
	if drift == nil {
		return true
	}
	expected := drift.ExpectedRows
	difference := observed - expected
	if difference < 0 {
		difference = -difference
	}
	if drift.MaxRows == 0 && drift.MaxBasisPoints == 0 {
		return difference != 0
	}
	if drift.MaxRows > 0 && difference > drift.MaxRows {
		return true
	}
	if drift.MaxBasisPoints > 0 && expected > 0 && difference*10_000 > expected*int64(drift.MaxBasisPoints) {
		return true
	}
	return false
}

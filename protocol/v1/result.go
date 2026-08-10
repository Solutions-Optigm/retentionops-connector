package protocolv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Status is the outcome of a job as the connector saw it.
type Status string

const (
	StatusCompleted Status = "COMPLETED"
	StatusDenied    Status = "DENIED"
	StatusFailed    Status = "FAILED"
	StatusPlanStale Status = "PLAN_STALE"
	// StatusCancelled means the connector observed a signed CANCEL decision at a batch
	// checkpoint. Statistics cover every batch committed before that decision.
	StatusCancelled Status = "CANCELLED"
	// StatusPartial is a success. A batched delete that reached its row or time ceiling
	// committed everything it reported and stopped on a batch boundary; the control plane
	// re-plans rather than treating it as an error.
	StatusPartial Status = "PARTIAL"
)

// DenialCode is why a connector refused. These strings are stable and never translated: an
// operator has to be able to tell a deliberate policy refusal from an outage without parsing
// prose, and a support conversation has to be able to quote one.
type DenialCode string

const (
	DeniedByLocalPolicy    DenialCode = "DENIED_BY_LOCAL_POLICY"
	DeniedUnknownSource    DenialCode = "DENIED_UNKNOWN_DATA_SOURCE"
	DeniedUnknownOperation DenialCode = "DENIED_UNKNOWN_OPERATION"
	DeniedTargetNotAllowed DenialCode = "DENIED_TARGET_NOT_ALLOWED"
	DeniedColumnNotAllowed DenialCode = "DENIED_COLUMN_NOT_ALLOWED"
	DeniedRowLimit         DenialCode = "DENIED_ROW_LIMIT_EXCEEDED"
	DeniedBatchLimit       DenialCode = "DENIED_BATCH_LIMIT_EXCEEDED"
	DeniedApprovalRequired DenialCode = "DENIED_APPROVAL_REQUIRED"
	DeniedApprovalExpired  DenialCode = "DENIED_APPROVAL_EXPIRED"
	DeniedSignatureInvalid DenialCode = "DENIED_SIGNATURE_INVALID"
	DeniedJobExpired       DenialCode = "DENIED_JOB_EXPIRED"
	DeniedNonceReplayed    DenialCode = "DENIED_NONCE_REPLAYED"
	DeniedWrongConnector   DenialCode = "DENIED_WRONG_CONNECTOR"
	DeniedWrongOrg         DenialCode = "DENIED_WRONG_ORGANIZATION"
	DeniedProtocolVersion  DenialCode = "DENIED_PROTOCOL_VERSION"
)

// FailureCode classifies an operational failure without quoting the driver.
//
// A PostgreSQL error message can contain a row value — that is what makes error passthrough a
// disclosure channel rather than a convenience. The connector logs the detail locally, where the
// customer already has the data, and sends only the class.
type FailureCode string

const (
	FailureUnreachable      FailureCode = "SOURCE_UNREACHABLE"
	FailureTLS              FailureCode = "TLS_VERIFICATION_FAILED"
	FailureAuthentication   FailureCode = "AUTHENTICATION_FAILED"
	FailureSecret           FailureCode = "SECRET_UNAVAILABLE"
	FailurePermission       FailureCode = "PERMISSION_DENIED"
	FailureStatementTimeout FailureCode = "STATEMENT_TIMEOUT"
	FailureLockTimeout      FailureCode = "LOCK_TIMEOUT"
	FailureTargetChanged    FailureCode = "TARGET_CHANGED"
	FailureInternal         FailureCode = "INTERNAL_ERROR"
)

// Column is table structure. Never a value.
type Column struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable,omitempty"`
	PrimaryKey bool   `json:"primary_key,omitempty"`
}

// Table is what discovery reports: names, types and an estimate. Reading a single row is not an
// operation this connector implements, so no code path exists that could fill this in from data.
type Table struct {
	Schema        string   `json:"schema"`
	Table         string   `json:"table"`
	EstimatedRows int64    `json:"estimated_rows,omitempty"`
	Columns       []Column `json:"columns"`
}

// Statistics is the whole of what leaves the customer's network about their data: counts, byte
// estimates, boundary timestamps and server metadata.
//
// The absence of a rows member here is the design. "Compute near the data, return evidence — not
// data" is enforced by the shape of this struct and by the matching "additionalProperties: false"
// in result.schema.json, so a future contributor cannot add an exfiltration path without
// changing a reviewed contract on both sides of the boundary.
type Statistics struct {
	CandidateRows   int64      `json:"candidate_rows,omitempty"`
	ResourceRows    int64      `json:"resource_rows,omitempty"`
	BlockedHoldRows int64      `json:"blocked_hold_rows,omitempty"`
	EstimatedBytes  int64      `json:"estimated_bytes,omitempty"`
	Oldest          *time.Time `json:"oldest,omitempty"`
	Newest          *time.Time `json:"newest,omitempty"`
	RowsDeleted     int64      `json:"rows_deleted,omitempty"`
	Batches         int        `json:"batches,omitempty"`
	Errors          int        `json:"errors,omitempty"`
	ObservedRows    int64      `json:"observed_rows,omitempty"`
	DatabaseVersion string     `json:"database_version,omitempty"`
	TLSMode         string     `json:"tls_mode,omitempty"`

	ReaderValidated   bool `json:"reader_validated,omitempty"`
	ExecutorValidated bool `json:"executor_validated,omitempty"`

	Tables []Table `json:"tables,omitempty"`
}

// JobResult is the signed record the connector returns.
type JobResult struct {
	ProtocolVersion string    `json:"protocol_version"`
	JobID           string    `json:"job_id"`
	OrganizationID  string    `json:"organization_id"`
	ConnectorID     string    `json:"connector_id"`
	DataSourceID    string    `json:"data_source_id"`
	Operation       Operation `json:"operation"`
	Status          Status    `json:"status"`

	DenialCode  DenialCode  `json:"denial_code,omitempty"`
	FailureCode FailureCode `json:"failure_code,omitempty"`

	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	ConnectorVersion string    `json:"connector_version"`

	PlanDigest   string `json:"plan_digest,omitempty"`
	ApprovalID   string `json:"approval_id,omitempty"`
	PolicyDigest string `json:"policy_digest,omitempty"`

	Statistics *Statistics `json:"statistics,omitempty"`

	ResultDigest string `json:"result_digest"`
	Signature    string `json:"signature"`
}

// Signer is the minimum a result needs: something holding the connector's private key.
type Signer interface {
	Sign(payload []byte) (string, error)
}

// Seal computes the result digest and signs it.
//
// Two separate attestations are on purpose. The digest fixes the content, and can be recomputed
// by anyone holding the document; the signature binds that digest to a connector identity. An
// auditor verifying an evidence bundle years later checks the first without needing our
// infrastructure, and the second without trusting our database.
func (r *JobResult) Seal(signer Signer) error {
	digest, err := DigestOf(r, "result_digest", "signature")
	if err != nil {
		return err
	}
	r.ResultDigest = digest
	signature, err := signer.Sign(SigningPayload(EvidenceDomain, []byte(digest)))
	if err != nil {
		return fmt.Errorf("protocol: sign result: %w", err)
	}
	r.Signature = signature
	return nil
}

// JobEvent is per-batch progress, delivered as the work happens so an interrupted job still
// leaves an accurate record of how far it got.
type JobEvent struct {
	ProtocolVersion string    `json:"protocol_version"`
	JobID           string    `json:"job_id"`
	OrganizationID  string    `json:"organization_id"`
	ConnectorID     string    `json:"connector_id"`
	Sequence        int       `json:"sequence"`
	EventType       string    `json:"event_type"`
	OccurredAt      time.Time `json:"occurred_at"`
	AffectedRows    int64     `json:"affected_rows,omitempty"`
	CumulativeRows  int64     `json:"cumulative_rows,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
}

// Event types carried by JobEvent.
const (
	EventAccepted       = "ACCEPTED"
	EventBatchCommitted = "BATCH_COMMITTED"
	EventPaused         = "PAUSED"
	EventResumed        = "RESUMED"
	EventAborted        = "ABORTED"
)

// SourceStatus is what the connector will say about a configured source. allowed_tables is a
// count rather than a list: the console needs to show the customer how wide they opened the
// door, and we have no business holding an inventory of their table names.
type SourceStatus struct {
	DataSourceID    string     `json:"data_source_id"`
	Type            string     `json:"type"`
	Status          string     `json:"status"`
	LastCheckAt     *time.Time `json:"last_check_at,omitempty"`
	DatabaseVersion string     `json:"database_version,omitempty"`
	TLSMode         string     `json:"tls_mode,omitempty"`

	ReaderValidated   bool `json:"reader_validated,omitempty"`
	ExecutorValidated bool `json:"executor_validated,omitempty"`
	AllowedTables     int  `json:"allowed_tables"`
}

// Source status values.
const (
	SourceReady        = "READY"
	SourceDegraded     = "DEGRADED"
	SourceUnconfigured = "UNCONFIGURED"
	SourceFailed       = "FAILED"
)

// Heartbeat announces liveness and the connector's self-declared shape.
type Heartbeat struct {
	ProtocolVersion  string         `json:"protocol_version"`
	OrganizationID   string         `json:"organization_id"`
	ConnectorID      string         `json:"connector_id"`
	ConnectorVersion string         `json:"connector_version"`
	OccurredAt       time.Time      `json:"occurred_at"`
	Platform         string         `json:"platform,omitempty"`
	Capabilities     []Operation    `json:"capabilities"`
	PolicyDigest     string         `json:"policy_digest"`
	Sources          []SourceStatus `json:"sources,omitempty"`
}

// EnrollmentRequest carries the public half of a key pair generated on the customer's host.
type EnrollmentRequest struct {
	ProtocolVersion  string `json:"protocol_version"`
	OrganizationID   string `json:"organization_id"`
	Token            string `json:"token"`
	PublicKey        string `json:"public_key"`
	ConnectorVersion string `json:"connector_version"`
	Platform         string `json:"platform,omitempty"`
}

// EnrollmentResponse hands back the connector's identity and the key it must pin.
type EnrollmentResponse struct {
	ProtocolVersion       string    `json:"protocol_version"`
	ConnectorID           string    `json:"connector_id"`
	OrganizationID        string    `json:"organization_id"`
	ControlPlanePublicKey string    `json:"control_plane_public_key"`
	IssuedAt              time.Time `json:"issued_at"`
}

// DecodeStrict parses raw into target, refusing unknown members. Used for every document the
// connector receives, for the same reason DecodeJob is strict.
func DecodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("protocol: malformed document: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("protocol: trailing content")
	}
	return nil
}

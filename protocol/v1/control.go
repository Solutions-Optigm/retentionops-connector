package protocolv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ControlAction is the closed set of decisions the control plane can return at a checkpoint.
// It changes whether the next batch may begin; it cannot alter the signed job or local policy.
type ControlAction string

const (
	ControlRun    ControlAction = "RUN"
	ControlPause  ControlAction = "PAUSE"
	ControlCancel ControlAction = "CANCEL"
)

// ExecutionControl is a signed, short-lived answer to one connector-generated challenge.
// Binding the answer to request_nonce prevents an earlier RUN answer from being replayed after
// an operator has requested a pause.
type ExecutionControl struct {
	ProtocolVersion  string        `json:"protocol_version"`
	JobID            string        `json:"job_id"`
	OrganizationID   string        `json:"organization_id"`
	ConnectorID      string        `json:"connector_id"`
	Action           ControlAction `json:"action"`
	ExecutionVersion int64         `json:"execution_version"`
	IssuedAt         time.Time     `json:"issued_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	RequestNonce     string        `json:"request_nonce"`
	Signature        string        `json:"signature"`
}

// DecodeControl parses a control document without tolerating extension members.
func DecodeControl(raw []byte) (*ExecutionControl, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var control ExecutionControl
	if err := decoder.Decode(&control); err != nil {
		return nil, fmt.Errorf("protocol: execution control is not valid v1: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("protocol: trailing content after execution control")
	}
	return &control, nil
}

// Validate checks the closed shape and the identities supplied by the request context.
func (c *ExecutionControl) Validate(jobID, organizationID, connectorID, requestNonce string) error {
	if c.ProtocolVersion != Version {
		return fmt.Errorf("protocol: unsupported control version %q", c.ProtocolVersion)
	}
	if c.JobID != jobID || c.OrganizationID != organizationID || c.ConnectorID != connectorID {
		return fmt.Errorf("protocol: execution control is addressed to another job or connector")
	}
	switch c.Action {
	case ControlRun, ControlPause, ControlCancel:
	default:
		return fmt.Errorf("protocol: unknown control action %q", c.Action)
	}
	if c.ExecutionVersion < 1 {
		return fmt.Errorf("protocol: execution_version must be positive")
	}
	if c.RequestNonce != requestNonce || !noncePattern.MatchString(c.RequestNonce) {
		return fmt.Errorf("protocol: execution control does not answer this request")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("protocol: execution control has an invalid validity window")
	}
	if !signaturePattern.MatchString(c.Signature) {
		return fmt.Errorf("protocol: execution control signature is malformed")
	}
	return nil
}

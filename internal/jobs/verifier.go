package jobs

import (
	"errors"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// ClockSkew is how far into the future an issued_at may sit before the job is treated as
// nonsense. Some skew is normal between two hosts; a lot of it is either a broken clock or an
// attempt to extend a job's life.
const ClockSkew = 2 * time.Minute

// Refusal is a verification failure carrying the stable code that goes back to the control plane.
type Refusal struct {
	Code   protocolv1.DenialCode
	Reason string
}

func (r *Refusal) Error() string { return string(r.Code) + ": " + r.Reason }

func refuse(code protocolv1.DenialCode, reason string) *Refusal {
	return &Refusal{Code: code, Reason: reason}
}

// AsRefusal extracts the refusal from an error, if it is one.
func AsRefusal(err error) (*Refusal, bool) {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal, true
	}
	return nil, false
}

// Verifier answers one question: is this document a job that this connector, right now, is
// obliged to consider running?
//
// It deliberately does not answer whether the job is *allowed* — that is the local safety
// policy's job, and separating them means a signature bug cannot be papered over by a policy
// rule, or the reverse.
type Verifier struct {
	identity *identity.Identity
	ledger   *ReplayLedger
	now      func() time.Time
}

// NewVerifier wires a verifier to an enrolled identity and a replay ledger.
func NewVerifier(id *identity.Identity, ledger *ReplayLedger) *Verifier {
	return &Verifier{identity: id, ledger: ledger, now: time.Now}
}

// Verify parses and authenticates raw.
//
// The envelope is returned alongside a refusal whenever it could be parsed at all, because the
// connector still owes the control plane a signed record naming the job it refused. A refusal
// nobody can see is indistinguishable from an outage.
//
// raw is used for the signature check rather than a re-encoding of the parsed struct. That is
// not an optimization: re-serializing a decoded document and hoping it reproduces the exact
// bytes the signer signed is how signature verification quietly stops meaning anything. The
// signature is checked against what actually arrived.
func (v *Verifier) Verify(raw []byte) (*protocolv1.JobEnvelope, error) {
	job, err := protocolv1.DecodeJob(raw)
	if err != nil {
		return nil, refuse(protocolv1.DeniedProtocolVersion, err.Error())
	}
	if err := job.Validate(); err != nil {
		return job, refuse(protocolv1.DeniedProtocolVersion, err.Error())
	}
	if job.OrganizationID != v.identity.OrganizationID {
		return job, refuse(protocolv1.DeniedWrongOrg, "job names another organization")
	}
	if job.ConnectorID != v.identity.ConnectorID {
		return job, refuse(protocolv1.DeniedWrongConnector, "job is addressed to another connector")
	}

	now := v.now()
	if !now.Before(job.ExpiresAt) {
		return job, refuse(protocolv1.DeniedJobExpired, "job expired at "+job.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if job.IssuedAt.After(now.Add(ClockSkew)) {
		return job, refuse(protocolv1.DeniedJobExpired, "job is issued too far in the future")
	}

	// The signature is checked before the nonce is consumed, so an unsigned flood cannot fill
	// the replay ledger with entries that would then refuse the control plane's real jobs.
	if err := v.verifySignature(raw, job.Signature); err != nil {
		return job, err
	}
	if err := v.ledger.Consume(job.Nonce); err != nil {
		if errors.Is(err, ErrReplayed) {
			return job, refuse(protocolv1.DeniedNonceReplayed, "this job has already been accepted once")
		}
		return job, err
	}
	return job, nil
}

func (v *Verifier) verifySignature(raw []byte, signature string) error {
	canonical, err := protocolv1.CanonicalizeRawWithout(raw, "signature")
	if err != nil {
		return refuse(protocolv1.DeniedSignatureInvalid, err.Error())
	}
	payload := protocolv1.SigningPayload(protocolv1.JobDomain, canonical)
	if err := v.identity.VerifyControlPlane(payload, signature); err != nil {
		return refuse(protocolv1.DeniedSignatureInvalid, "signature does not verify against the pinned control-plane key")
	}
	return nil
}

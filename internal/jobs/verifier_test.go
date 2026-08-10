package jobs

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

const (
	organization = "11111111-1111-4111-8111-111111111111"
	connector    = "22222222-2222-4222-8222-222222222222"
	job          = "33333333-3333-4333-8333-333333333333"
	source       = "44444444-4444-4444-8444-444444444444"
	approval     = "55555555-5555-4555-8555-555555555555"
	planDigest   = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

// harness is a connector that has enrolled against a control plane we also hold the key for, so
// a test can produce genuinely valid jobs — and genuinely invalid ones.
type harness struct {
	verifier     *Verifier
	controlPlane ed25519.PrivateKey
	imposter     ed25519.PrivateKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	directory := t.TempDir()

	_, connectorKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate connector key: %v", err)
	}
	controlPlanePublic, controlPlanePrivate, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate control-plane key: %v", err)
	}
	_, imposter, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate imposter key: %v", err)
	}

	if err := identity.Save(directory, connectorKey, identity.Enrollment{
		ConnectorID:           connector,
		OrganizationID:        organization,
		ControlPlanePublicKey: identity.EncodePublic(controlPlanePublic),
		IssuedAt:              time.Now(),
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	loaded, err := identity.Load(directory)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	ledger, err := NewReplayLedger(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	return &harness{
		verifier:     NewVerifier(loaded, ledger),
		controlPlane: controlPlanePrivate,
		imposter:     imposter,
	}
}

func envelope(mutate ...func(*protocolv1.JobEnvelope)) *protocolv1.JobEnvelope {
	now := time.Now().UTC().Truncate(time.Second)
	document := &protocolv1.JobEnvelope{
		ProtocolVersion: protocolv1.Version,
		JobID:           job,
		OrganizationID:  organization,
		ConnectorID:     connector,
		DataSourceID:    source,
		Operation:       protocolv1.OpDelete,
		Target:          &protocolv1.Target{Schema: "application", Table: "audit_logs"},
		Predicate: &protocolv1.Predicate{
			Type:   protocolv1.PredicateBefore,
			Column: "created_at",
			Value:  now.AddDate(-7, 0, 0),
		},
		Holds:      []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}},
		Limits:     &protocolv1.Limits{BatchSize: 1000, MaxRows: 50000, StatementTimeoutSeconds: 30},
		Drift:      &protocolv1.Drift{ExpectedRows: 10000, MaxRows: 50, MaxBasisPoints: 50},
		PlanDigest: planDigest,
		Approval: &protocolv1.Approval{
			ID:         approval,
			ApprovedAt: now.Add(-time.Hour),
			ExpiresAt:  now.Add(time.Hour),
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     newNonce(),
	}
	for _, apply := range mutate {
		apply(document)
	}
	return document
}

var nonceCounter int

// newNonce keeps every job in a test distinct, so a replay is something a test opts into rather
// than something it stumbles over.
func newNonce() string {
	nonceCounter++
	raw := make([]byte, 16)
	raw[0] = byte(nonceCounter)
	raw[1] = byte(nonceCounter >> 8)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// sign produces the bytes that would arrive over the wire.
func sign(t *testing.T, key ed25519.PrivateKey, document *protocolv1.JobEnvelope) []byte {
	t.Helper()
	canonical, err := protocolv1.CanonicalizeWithout(document, "signature")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	payload := protocolv1.SigningPayload(protocolv1.JobDomain, canonical)
	document.Signature = "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestAGenuineJobIsAccepted(t *testing.T) {
	h := newHarness(t)
	verified, err := h.verifier.Verify(sign(t, h.controlPlane, envelope()))
	if err != nil {
		t.Fatalf("expected the job to verify, got %v", err)
	}
	if verified.JobID != job {
		t.Fatalf("unexpected job id %q", verified.JobID)
	}
}

// Each case is a way a job can be wrong, and the stable code the connector owes the control plane
// in return. A refusal that reports the wrong code is nearly as bad as no refusal: an operator
// diagnoses the wrong problem.
func TestTheVerifierRefuses(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, h *harness) []byte
		code    protocolv1.DenialCode
	}{
		{
			name: "a signature from a key we never pinned",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.imposter, envelope())
			},
			code: protocolv1.DeniedSignatureInvalid,
		},
		{
			name: "a job whose body was altered after signing",
			prepare: func(t *testing.T, h *harness) []byte {
				raw := sign(t, h.controlPlane, envelope())
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				// The classic attack: keep the signature, widen the blast radius.
				document["limits"].(map[string]any)["max_rows"] = 10_000_000
				tampered, err := json.Marshal(document)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				return tampered
			},
			code: protocolv1.DeniedSignatureInvalid,
		},
		{
			name: "a job addressed to another connector",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.ConnectorID = "99999999-9999-4999-8999-999999999999"
				}))
			},
			code: protocolv1.DeniedWrongConnector,
		},
		{
			name: "a job addressed to another organization",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.OrganizationID = "99999999-9999-4999-8999-999999999999"
				}))
			},
			code: protocolv1.DeniedWrongOrg,
		},
		{
			name: "a job that has expired",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.IssuedAt = time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
					j.ExpiresAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
				}))
			},
			code: protocolv1.DeniedJobExpired,
		},
		{
			name: "a job issued implausibly far in the future",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.IssuedAt = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
					j.ExpiresAt = time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
				}))
			},
			code: protocolv1.DeniedJobExpired,
		},
		{
			name: "an operation this connector does not implement",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.Operation = "POSTGRES_TRUNCATE"
				}))
			},
			code: protocolv1.DeniedProtocolVersion,
		},
		{
			name: "a destructive job with no approval",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.Approval = nil
				}))
			},
			code: protocolv1.DeniedProtocolVersion,
		},
		{
			name: "a destructive job with no drift policy",
			prepare: func(t *testing.T, h *harness) []byte {
				return sign(t, h.controlPlane, envelope(func(j *protocolv1.JobEnvelope) {
					j.Drift = nil
				}))
			},
			code: protocolv1.DeniedProtocolVersion,
		},
		{
			name: "a document carrying a member this connector does not understand",
			prepare: func(t *testing.T, h *harness) []byte {
				raw := sign(t, h.controlPlane, envelope())
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				document["sql"] = "DELETE FROM users"
				widened, err := json.Marshal(document)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				return widened
			},
			code: protocolv1.DeniedProtocolVersion,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			_, err := h.verifier.Verify(testCase.prepare(t, h))
			refusal, ok := AsRefusal(err)
			if !ok {
				t.Fatalf("expected a refusal, got %v", err)
			}
			if refusal.Code != testCase.code {
				t.Fatalf("expected %s, got %s (%s)", testCase.code, refusal.Code, refusal.Reason)
			}
		})
	}
}

func TestAReplayedJobIsRefusedTheSecondTime(t *testing.T) {
	h := newHarness(t)
	raw := sign(t, h.controlPlane, envelope())

	if _, err := h.verifier.Verify(raw); err != nil {
		t.Fatalf("the first delivery must be accepted, got %v", err)
	}
	_, err := h.verifier.Verify(raw)
	refusal, ok := AsRefusal(err)
	if !ok || refusal.Code != protocolv1.DeniedNonceReplayed {
		t.Fatalf("expected DENIED_NONCE_REPLAYED on the second delivery, got %v", err)
	}
}

// The signature is checked before the nonce is consumed. Otherwise anyone able to reach this
// connector could burn the nonces of jobs it has not received yet, and the control plane's real
// work would start being refused as replays.
func TestAnUnsignedFloodCannotPoisonTheReplayLedger(t *testing.T) {
	h := newHarness(t)
	document := envelope()
	forged := sign(t, h.imposter, document)

	for range 5 {
		if _, err := h.verifier.Verify(forged); err == nil {
			t.Fatal("a forged job must never be accepted")
		}
	}

	// Same nonce, this time correctly signed: it must still be usable.
	document.Signature = ""
	if _, err := h.verifier.Verify(sign(t, h.controlPlane, document)); err != nil {
		t.Fatalf("the genuine job must still be accepted, got %v", err)
	}
}

// A connector process restarted mid-flight must still recognise a nonce it consumed before the
// restart. An in-memory set would get this silently wrong, which is why the ledger is on disk.
func TestTheLedgerSurvivesARestart(t *testing.T) {
	directory := t.TempDir()
	first, err := NewReplayLedger(directory, time.Hour)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if err := first.Consume("restart-nonce-aaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("first use must succeed: %v", err)
	}

	second, err := NewReplayLedger(directory, time.Hour)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := second.Consume("restart-nonce-aaaaaaaaaaaaaa"); err != ErrReplayed {
		t.Fatalf("expected ErrReplayed after restart, got %v", err)
	}
}

// Two nonces differing only in case must stay distinct. On a case-insensitive filesystem — macOS
// by default — naming ledger entries after the nonce itself would silently refuse a legitimate
// job, which is why entries are named by digest.
func TestTheLedgerIsNotFooledByACaseInsensitiveFilesystem(t *testing.T) {
	ledger, err := NewReplayLedger(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if err := ledger.Consume("AbCdEfGhIjKlMnOpQrSt"); err != nil {
		t.Fatalf("first nonce: %v", err)
	}
	if err := ledger.Consume("aBcDeFgHiJkLmNoPqRsT"); err != nil {
		t.Fatalf("a nonce differing only in case must be accepted, got %v", err)
	}
}

func TestPruneRemovesOnlyExpiredEntries(t *testing.T) {
	ledger, err := NewReplayLedger(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if err := ledger.Consume("recent-nonce-aaaaaaaaaaaa"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	if removed, err := ledger.Prune(time.Now()); err != nil || removed != 0 {
		t.Fatalf("a fresh entry must survive: removed=%d err=%v", removed, err)
	}
	// Pruning from a point far in the future puts every entry past the retention window.
	if removed, err := ledger.Prune(time.Now().Add(48 * time.Hour)); err != nil || removed != 1 {
		t.Fatalf("an expired entry must be pruned: removed=%d err=%v", removed, err)
	}
	if err := ledger.Consume("recent-nonce-aaaaaaaaaaaa"); err != nil {
		t.Fatalf("a pruned nonce is reusable, got %v", err)
	}
}

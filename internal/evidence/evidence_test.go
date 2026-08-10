package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// Between planning and execution the table keeps living. These cases are the boundary between
// "the approval still describes reality" and "re-plan": getting them wrong means either
// refusing every job on a busy table, or deleting rows nobody approved.
func TestDriftTolerance(t *testing.T) {
	cases := []struct {
		name     string
		drift    *protocolv1.Drift
		observed int64
		exceeded bool
	}{
		{name: "no drift declared means any change is too much", drift: &protocolv1.Drift{ExpectedRows: 100}, observed: 101, exceeded: true},
		{name: "an exact match always passes", drift: &protocolv1.Drift{ExpectedRows: 100}, observed: 100},
		{name: "inside the absolute tolerance", drift: &protocolv1.Drift{ExpectedRows: 24391, MaxRows: 100}, observed: 24405},
		{name: "outside the absolute tolerance", drift: &protocolv1.Drift{ExpectedRows: 24391, MaxRows: 100}, observed: 24500, exceeded: true},
		{name: "fewer rows than planned also counts as drift", drift: &protocolv1.Drift{ExpectedRows: 24391, MaxRows: 100}, observed: 24000, exceeded: true},
		{name: "inside the percentage tolerance", drift: &protocolv1.Drift{ExpectedRows: 10000, MaxBasisPoints: 50}, observed: 10050},
		{name: "outside the percentage tolerance", drift: &protocolv1.Drift{ExpectedRows: 10000, MaxBasisPoints: 50}, observed: 10051, exceeded: true},
		{name: "an absent drift block is not a licence to proceed blind", drift: nil, observed: 999999, exceeded: true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := DriftExceeded(testCase.drift, testCase.observed); got != testCase.exceeded {
				t.Fatalf("expected exceeded=%v, got %v", testCase.exceeded, got)
			}
		})
	}
}

type testSigner struct{ private ed25519.PrivateKey }

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testSigner{private: private}
}

func (s testSigner) Sign(payload []byte) (string, error) {
	return "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, payload)), nil
}

// A refusal is a signed record, not a silent drop. The control plane has to learn that it asked
// for something the customer forbade, and the customer has to be able to prove it did.
func TestARefusalIsStillSignedEvidence(t *testing.T) {
	builder := &Builder{
		OrganizationID: "11111111-1111-4111-8111-111111111111",
		ConnectorID:    "22222222-2222-4222-8222-222222222222",
		Version:        "0.1.0",
		PolicyDigest:   "sha256:" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	job := &protocolv1.JobEnvelope{
		JobID:        "33333333-3333-4333-8333-333333333333",
		DataSourceID: "44444444-4444-4444-8444-444444444444",
		Operation:    protocolv1.OpDelete,
	}
	result, err := builder.Refusal(job, protocolv1.DeniedTargetNotAllowed, time.Now(), newTestSigner(t))
	if err != nil {
		t.Fatalf("sealing a refusal failed: %v", err)
	}
	if result.Status != protocolv1.StatusDenied || result.DenialCode != protocolv1.DeniedTargetNotAllowed {
		t.Fatalf("unexpected refusal record: %+v", result)
	}
	if !protocolv1.IsDigest(result.ResultDigest) {
		t.Fatalf("a refusal must carry a result digest, got %q", result.ResultDigest)
	}
	if result.PolicyDigest != builder.PolicyDigest {
		t.Fatal("a refusal must name the policy that produced it")
	}
	if result.Statistics != nil {
		t.Fatal("a refusal must not carry statistics: nothing was measured")
	}
}

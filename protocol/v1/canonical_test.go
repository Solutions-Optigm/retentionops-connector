package protocolv1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The digest is the thing a signature is taken over. If two implementations disagree about the
// canonical form by one byte, every signature fails in production rather than in a test — so the
// rules are pinned here explicitly rather than left to whatever encoding/json happens to do.
func TestCanonicalFormIsPinned(t *testing.T) {
	cases := []struct {
		name     string
		value    any
		expected string
	}{
		{
			name:     "members are ordered, not preserved",
			value:    map[string]any{"b": 1, "a": 2, "C": 3},
			expected: `{"C":3,"a":2,"b":1}`,
		},
		{
			name:     "no whitespace anywhere",
			value:    map[string]any{"nested": map[string]any{"x": []any{1, 2}}},
			expected: `{"nested":{"x":[1,2]}}`,
		},
		{
			name:     "only the mandatory escapes and the short forms",
			value:    map[string]any{"s": "a\"b\\c\nd\te"},
			expected: `{"s":"a\"b\\c\nd\te"}`,
		},
		{
			name:     "other control characters become a \\u00xx escape",
			value:    map[string]any{"s": "a\u0001b"},
			expected: `{"s":"a\u0001b"}`,
		},
		{
			name:     "non-ASCII stays literal UTF-8",
			value:    map[string]any{"s": "vérité"},
			expected: `{"s":"vérité"}`,
		},
		{
			name:     "null and booleans",
			value:    map[string]any{"a": nil, "b": true},
			expected: `{"a":null,"b":true}`,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			produced, err := Canonicalize(testCase.value)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(produced) != testCase.expected {
				t.Fatalf("expected %s, got %s", testCase.expected, produced)
			}
		})
	}
}

// A float in a signed document would mean two canonicalizers have to agree on every double.
// Refusing is cheaper than that guarantee, and the schemas declare integers throughout.
func TestFloatsAreRefusedRatherThanSerialized(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"ratio": 1.5}); err == nil {
		t.Fatal("a float must be refused")
	}
	if _, err := Canonicalize(map[string]any{"whole": 3}); err != nil {
		t.Fatalf("an integer must be accepted: %v", err)
	}
}

func TestCanonicalizeWithoutRemovesOnlyTheNamedMember(t *testing.T) {
	document := map[string]any{"a": 1, "signature": "ed25519:x", "b": 2}
	produced, err := CanonicalizeWithout(document, "signature")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(produced) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical form: %s", produced)
	}
}

// Verification must work from the received bytes. This proves the raw path and the struct path
// agree, which is what lets a signer canonicalize its own struct and a verifier canonicalize the
// bytes that arrived.
func TestRawAndStructCanonicalizationAgree(t *testing.T) {
	job := JobEnvelope{
		ProtocolVersion: Version,
		JobID:           "33333333-3333-4333-8333-333333333333",
		OrganizationID:  "11111111-1111-4111-8111-111111111111",
		ConnectorID:     "22222222-2222-4222-8222-222222222222",
		DataSourceID:    "44444444-4444-4444-8444-444444444444",
		Operation:       OpCount,
		Target:          &Target{Schema: "application", Table: "audit_logs"},
		Predicate: &Predicate{
			Type:   PredicateBefore,
			Column: "created_at",
			Value:  time.Date(2019, 8, 7, 0, 0, 0, 0, time.UTC),
		},
		Limits:    &Limits{BatchSize: 1000, MaxRows: 50000, StatementTimeoutSeconds: 30},
		IssuedAt:  time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC),
		Nonce:     "AAAAAAAAAAAAAAAAAAAAAA",
		Signature: "ed25519:" + strings.Repeat("A", 86) + "==",
	}
	fromStruct, err := CanonicalizeWithout(job, "signature")
	if err != nil {
		t.Fatalf("struct path: %v", err)
	}
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fromRaw, err := CanonicalizeRawWithout(encoded, "signature")
	if err != nil {
		t.Fatalf("raw path: %v", err)
	}
	if string(fromStruct) != string(fromRaw) {
		t.Fatalf("the two paths disagree:\n struct %s\n raw    %s", fromStruct, fromRaw)
	}
}

func TestSigningPayloadsAreDomainSeparated(t *testing.T) {
	body := []byte("{}")
	job := string(SigningPayload(JobDomain, body))
	evidence := string(SigningPayload(EvidenceDomain, body))
	if job == evidence {
		t.Fatal("a job signature must not be usable as an evidence signature")
	}
	control := string(SigningPayload(ControlDomain, body))
	if control == job || control == evidence {
		t.Fatal("a checkpoint control signature must not be usable as another document type")
	}
	if !strings.HasPrefix(job, JobDomain+"\n") {
		t.Fatalf("expected a domain prefix, got %q", job)
	}
}

func TestExecutionControlIsBoundToTheRequestContext(t *testing.T) {
	control := ExecutionControl{
		ProtocolVersion:  Version,
		JobID:            "33333333-3333-4333-8333-333333333333",
		OrganizationID:   "11111111-1111-4111-8111-111111111111",
		ConnectorID:      "22222222-2222-4222-8222-222222222222",
		Action:           ControlPause,
		ExecutionVersion: 7,
		IssuedAt:         time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(30 * time.Second),
		RequestNonce:     "AAAAAAAAAAAAAAAAAAAAAA",
		Signature:        "ed25519:" + strings.Repeat("A", 86) + "==",
	}
	if err := control.Validate(control.JobID, control.OrganizationID, control.ConnectorID, control.RequestNonce); err != nil {
		t.Fatalf("valid control refused: %v", err)
	}
	if err := control.Validate(control.JobID, control.OrganizationID, control.ConnectorID, "BBBBBBBBBBBBBBBBBBBBBB"); err == nil {
		t.Fatal("a control answer replayed against another challenge must be refused")
	}
}

func TestRequestSignaturesCoverMethodPathAndBody(t *testing.T) {
	base := string(RequestSigningPayload("GET", "/connector/v1/jobs/next?wait=30", "t", "n", nil))
	for _, variant := range []string{
		string(RequestSigningPayload("POST", "/connector/v1/jobs/next?wait=30", "t", "n", nil)),
		string(RequestSigningPayload("GET", "/connector/v1/jobs/next?wait=5", "t", "n", nil)),
		string(RequestSigningPayload("GET", "/connector/v1/jobs/next?wait=30", "t2", "n", nil)),
		string(RequestSigningPayload("GET", "/connector/v1/jobs/next?wait=30", "t", "n2", nil)),
		string(RequestSigningPayload("GET", "/connector/v1/jobs/next?wait=30", "t", "n", []byte("{}"))),
	} {
		if variant == base {
			t.Fatal("changing a covered field must change the signed payload")
		}
	}
}

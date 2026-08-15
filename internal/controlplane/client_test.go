package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

func TestAcceptNoContent(t *testing.T) {
	t.Parallel()

	if err := acceptNoContent(ErrNoWork); err != nil {
		t.Fatalf("204 response must be accepted by write endpoints: %v", err)
	}
	want := errors.New("network failure")
	if got := acceptNoContent(want); !errors.Is(got, want) {
		t.Fatalf("non-204 error was hidden: %v", got)
	}
}

func TestControlPlaneErrorExposesOnlyTheStableCode(t *testing.T) {
	t.Parallel()

	client, err := New("https://control.invalid", "", "test", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"error":{"code":"ENROLLMENT_TOKEN_INVALID","message":"secret token was rtc_sensitive"}}`,
			)),
			Request: request,
		}, nil
	})

	_, err = client.do(context.Background(), http.MethodPost, "/connector/v1/enroll", nil, false)
	if err == nil {
		t.Fatal("HTTP 400 must fail")
	}
	message := err.Error()
	if !strings.Contains(message, "HTTP 400 (ENROLLMENT_TOKEN_INVALID)") {
		t.Fatalf("stable error code is missing: %q", message)
	}
	if strings.Contains(message, "rtc_sensitive") || strings.Contains(message, "secret token") {
		t.Fatalf("remote error details leaked: %q", message)
	}
}

func TestControlPlaneErrorRejectsUnsafeCode(t *testing.T) {
	t.Parallel()

	client, err := New("https://control.invalid", "", "test", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"error":{"code":"INVALID\nrtc_sensitive","message":"must stay hidden"}}`,
			)),
			Request: request,
		}, nil
	})

	_, err = client.do(context.Background(), http.MethodPost, "/connector/v1/enroll", nil, false)
	if err == nil {
		t.Fatal("HTTP 400 must fail")
	}
	if got, want := err.Error(), "controlplane: POST /connector/v1/enroll answered HTTP 400"; got != want {
		t.Fatalf("unsafe remote response was not hidden: got %q, want %q", got, want)
	}
}

func TestControlVerifiesThePinnedSignatureAndFreshChallenge(t *testing.T) {
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, connectorPrivate, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := identity.Save(directory, connectorPrivate, identity.Enrollment{
		ConnectorID:           "22222222-2222-4222-8222-222222222222",
		OrganizationID:        "11111111-1111-4111-8111-111111111111",
		ControlPlanePublicKey: identity.EncodePublic(controlPublic),
		IssuedAt:              time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(directory)
	if err != nil {
		t.Fatal(err)
	}

	client, err := New("https://control.invalid", "", "test", id, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		challenge := request.URL.Query().Get("request_nonce")
		control := protocolv1.ExecutionControl{
			ProtocolVersion:  protocolv1.Version,
			JobID:            "33333333-3333-4333-8333-333333333333",
			OrganizationID:   id.OrganizationID,
			ConnectorID:      id.ConnectorID,
			Action:           protocolv1.ControlPause,
			ExecutionVersion: 7,
			IssuedAt:         time.Now().UTC(),
			ExpiresAt:        time.Now().UTC().Add(30 * time.Second),
			RequestNonce:     challenge,
		}
		canonical, canonicalErr := protocolv1.CanonicalizeWithout(control, "signature")
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		control.Signature = "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(
			controlPrivate, protocolv1.SigningPayload(protocolv1.ControlDomain, canonical),
		))
		body, encodeErr := json.Marshal(control)
		if encodeErr != nil {
			return nil, encodeErr
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Request:    request,
		}, nil
	})
	control, err := client.Control(context.Background(), "33333333-3333-4333-8333-333333333333")
	if err != nil {
		t.Fatalf("signed control refused: %v", err)
	}
	if control.Action != protocolv1.ControlPause || !strings.HasPrefix(control.Signature, "ed25519:") {
		t.Fatalf("unexpected control: %+v", control)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

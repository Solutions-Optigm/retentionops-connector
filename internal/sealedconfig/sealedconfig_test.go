package sealedconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	organization = "d0555ae5-d89f-41e8-ba24-31d238ffb8c8"
	connector    = "4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52"
	source       = "a56f11c4-1051-4972-b838-2f1faa90af19"
)

func recipientKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func envelopeFor(now time.Time) Envelope {
	return Envelope{
		EnvelopeID: "b7c1d2e3-4f56-4789-a0b1-c2d3e4f56789", OrganizationID: organization,
		SourceID: source, ConnectorID: connector,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func configuration() SourceConfiguration {
	return SourceConfiguration{
		Host: "postgres.internal", Port: 5432, Database: "application",
		ReaderRole: "retentionops_reader", TLSMode: "verify-full",
	}
}

func TestASealedConfigurationOpensForItsRecipient(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)

	sealed, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(sealed, key, connector, organization, now)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Host != "postgres.internal" || opened.Port != 5432 || opened.TLSMode != "verify-full" {
		t.Fatalf("configuration did not survive the round trip: %+v", opened)
	}
}

// The whole design rests on this: a control plane holding the envelope holds no way in.
func TestAnEnvelopeDoesNotOpenForAnyOtherKey(t *testing.T) {
	now := time.Now().UTC()
	sealed, err := Seal(configuration(), recipientKey(t).PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, recipientKey(t), connector, organization, now); !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("a foreign key opened the envelope: %v", err)
	}
}

// Every field outside the ciphertext is authenticated, so a relay cannot re-address an envelope.
func TestEveryBoundFieldIsAuthenticated(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)
	sealed, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}

	for name, tamper := range map[string]func(Envelope) Envelope{
		"envelope_id": func(e Envelope) Envelope { e.EnvelopeID = "00000000-0000-4000-8000-000000000000"; return e },
		"source_id":   func(e Envelope) Envelope { e.SourceID = "00000000-0000-4000-8000-000000000000"; return e },
		"issued_at":   func(e Envelope) Envelope { e.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339); return e },
		"expires_at":  func(e Envelope) Envelope { e.ExpiresAt = now.Add(9 * time.Hour).Format(time.RFC3339); return e },
		"nonce":       func(e Envelope) Envelope { e.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12)); return e },
	} {
		if _, err := Open(tamper(sealed), key, connector, organization, now); err == nil {
			t.Fatalf("%s was altered without the envelope refusing", name)
		}
	}
}

// A connector must not apply an envelope addressed to a different one, even holding a key that
// would open it -- which is the case for two sources behind the same connector identity.
func TestAnEnvelopeIsRefusedForAnotherIdentity(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)
	sealed, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(sealed, key, "00000000-0000-4000-8000-000000000000", organization, now); !errors.Is(err, ErrWrongRecipient) {
		t.Fatal("an envelope for another connector was accepted")
	}
	if _, err := Open(sealed, key, connector, "00000000-0000-4000-8000-000000000000", now); !errors.Is(err, ErrWrongRecipient) {
		t.Fatal("an envelope for another organization was accepted")
	}
}

func TestExpiryToleratesSkewButNotStaleness(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)
	sealed, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}

	// Sealing happens in a browser on somebody's laptop; the drift is theirs.
	if _, err := Open(sealed, key, connector, organization, now.Add(time.Hour+ClockSkew-time.Minute)); err != nil {
		t.Fatalf("a clock a few minutes out refused a valid envelope: %v", err)
	}
	if _, err := Open(sealed, key, connector, organization, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatal("an expired envelope was accepted")
	}
	future := envelopeFor(now.Add(time.Hour))
	sealedFuture, err := Seal(configuration(), key.PublicKey(), future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealedFuture, key, connector, organization, now); !errors.Is(err, ErrNotYetValid) {
		t.Fatal("an envelope issued in the future was accepted")
	}
}

func TestAnOversizedEnvelopeIsRefusedBeforeDecryption(t *testing.T) {
	now := time.Now().UTC()
	sealed := envelopeFor(now)
	sealed.Version = Version
	sealed.EphemeralKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	sealed.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, MaxCiphertextBytes+1))

	if _, err := Open(sealed, recipientKey(t), connector, organization, now); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an oversized envelope was not refused by length: %v", err)
	}
}

// Two envelopes to the same connector must not share a key stream. A repeated (key, nonce) pair
// in GCM loses confidentiality and authenticity at once.
func TestEachEnvelopeUsesAFreshEphemeralKey(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)
	first, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}
	if first.EphemeralKey == second.EphemeralKey {
		t.Fatal("two envelopes reused one ephemeral key")
	}
	if first.Nonce == second.Nonce {
		t.Fatal("two envelopes reused one nonce")
	}
	if first.Ciphertext == second.Ciphertext {
		t.Fatal("identical plaintexts produced identical ciphertexts")
	}
}

// These errors travel into logs the control plane can eventually read.
func TestNoErrorQuotesPlaintextOrKeyMaterial(t *testing.T) {
	now := time.Now().UTC()
	key := recipientKey(t)
	sealed, err := Seal(configuration(), key.PublicKey(), envelopeFor(now))
	if err != nil {
		t.Fatal(err)
	}
	sealed.Ciphertext = base64.StdEncoding.EncodeToString([]byte("tampered"))

	_, openErr := Open(sealed, key, connector, organization, now)
	if openErr == nil {
		t.Fatal("a tampered ciphertext opened")
	}
	for _, secret := range []string{"postgres.internal", "retentionops_reader", "application", sealed.Ciphertext} {
		if strings.Contains(openErr.Error(), secret) {
			t.Fatalf("an error quoted %q", secret)
		}
	}
}

// The AAD is the contract the browser has to reproduce byte for byte. Pinned here so a change to
// the field order, the length prefix or the domain string cannot pass unnoticed on one side.
func TestAdditionalDataIsAFixedByteLayout(t *testing.T) {
	envelope := Envelope{
		Version: 1, EnvelopeID: "e", OrganizationID: "o", SourceID: "s", ConnectorID: "c",
		IssuedAt: "i", ExpiresAt: "x",
	}
	got := AdditionalData(envelope)

	want := []byte{}
	for _, field := range []string{domain, "1", "e", "o", "s", "c", "i", "x"} {
		want = append(want, byte(len(field)>>8), byte(len(field)))
		want = append(want, field...)
	}
	if string(got) != string(want) {
		t.Fatalf("AAD layout changed:\n got %q\nwant %q", got, want)
	}
	if !strings.HasPrefix(string(got[2:]), domain) {
		t.Fatal("the AAD no longer starts with its domain separator")
	}
}

// Written for the TypeScript suite to open with WebCrypto. Interoperability is a property of the
// bytes, and a vector produced by the implementation that ships is the only honest way to check
// the other side against it.
func TestWriteCrossLanguageVector(t *testing.T) {
	if os.Getenv("RETENTIONOPS_WRITE_VECTOR") == "" {
		t.Skip("set RETENTIONOPS_WRITE_VECTOR to regenerate the WebCrypto vector")
	}
	key := recipientKey(t)
	issued := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	envelope := Envelope{
		EnvelopeID: "b7c1d2e3-4f56-4789-a0b1-c2d3e4f56789", OrganizationID: organization,
		SourceID: source, ConnectorID: connector,
		IssuedAt:  issued.Format(time.RFC3339),
		ExpiresAt: issued.Add(time.Hour).Format(time.RFC3339),
	}
	sealed, err := Seal(configuration(), key.PublicKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"recipient_private_key": base64.StdEncoding.EncodeToString(key.Bytes()),
		"recipient_public_key":  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		"envelope":              sealed,
		"configuration":         configuration(),
		"additional_data":       base64.StdEncoding.EncodeToString(AdditionalData(sealed)),
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "webcrypto-vector.json")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// The other direction. Opening Go's own bytes proves the framing is read the same way; this
// proves it is written the same way, which is the direction that actually runs in production —
// a browser seals, this connector opens.
func TestOpensAnEnvelopeSealedByTheBrowser(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "browser-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RecipientPrivateKey string              `json:"recipient_private_key"`
		Envelope            Envelope            `json:"envelope"`
		Configuration       SourceConfiguration `json:"configuration"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(vector.RecipientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := time.Parse(time.RFC3339, vector.Envelope.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(vector.Envelope, key, vector.Envelope.ConnectorID, vector.Envelope.OrganizationID, issued)
	if err != nil {
		t.Fatalf("a browser-sealed envelope did not open: %v", err)
	}
	if opened.Host != vector.Configuration.Host || opened.Port != vector.Configuration.Port {
		t.Fatalf("configuration differs: %+v", opened)
	}
	if opened.TLSMode != vector.Configuration.TLSMode || opened.ReaderRole != vector.Configuration.ReaderRole {
		t.Fatalf("configuration differs: %+v", opened)
	}
}

// At-least-once delivery meets an application that must happen once. This is the property the
// envelope id exists for, and it has to survive a restart -- an in-memory set would not.
func TestARedeliveredEnvelopeReportsTheFirstOutcomeAndIsNotReapplied(t *testing.T) {
	directory := t.TempDir()
	ledger, err := NewLedger(directory)
	if err != nil {
		t.Fatal(err)
	}
	const envelope = "b7c1d2e3-4f56-4789-a0b1-c2d3e4f56789"

	if _, seen, err := ledger.Outcome(envelope); err != nil || seen {
		t.Fatalf("an unseen envelope was reported as seen: seen=%v err=%v", seen, err)
	}
	if err := ledger.Record(envelope, OutcomeApplied); err != nil {
		t.Fatal(err)
	}

	// A fresh ledger over the same directory is what a restarted connector sees.
	restarted, err := NewLedger(directory)
	if err != nil {
		t.Fatal(err)
	}
	outcome, seen, err := restarted.Outcome(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !seen || outcome != OutcomeApplied {
		t.Fatalf("a restart forgot an applied envelope: seen=%v outcome=%q", seen, outcome)
	}
}

// The first answer may already have reached the control plane. A redelivery must not rewrite it.
func TestAnOutcomeIsWrittenOnceAndNeverRevised(t *testing.T) {
	ledger, err := NewLedger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const envelope = "b7c1d2e3-4f56-4789-a0b1-c2d3e4f56789"

	if err := ledger.Record(envelope, OutcomeApplied); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record(envelope, OutcomeRefusedInvalid); err != nil {
		t.Fatal(err)
	}
	outcome, _, err := ledger.Outcome(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("a redelivery revised history: %q", outcome)
	}
}

// Two envelope ids differing only in case are different envelopes. On a case-insensitive
// filesystem, naming entries after the id itself would silently merge them.
func TestEnvelopesDifferingOnlyInCaseAreDistinctEntries(t *testing.T) {
	ledger, err := NewLedger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Record("AAAA-bbbb", OutcomeApplied); err != nil {
		t.Fatal(err)
	}
	if _, seen, err := ledger.Outcome("aaaa-BBBB"); err != nil || seen {
		t.Fatalf("a different envelope was treated as already applied: seen=%v", seen)
	}
}

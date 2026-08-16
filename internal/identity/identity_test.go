package identity

import (
	"bytes"
	"testing"
)

// The published key has to survive a retry: a configuration sealed while the operator was
// re-running enrolment must still open afterwards, or the console silently produces envelopes
// the connector cannot read.
func TestTheEncryptionKeyIsStableForOneIdentity(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateEnrollmentAttempt(directory, "d0555ae5-d89f-41e8-ba24-31d238ffb8c8")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateEnrollmentAttempt(directory, "d0555ae5-d89f-41e8-ba24-31d238ffb8c8")
	if err != nil {
		t.Fatal(err)
	}

	one, err := first.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	two, err := second.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if EncodePublicEncryption(one.PublicKey()) != EncodePublicEncryption(two.PublicKey()) {
		t.Fatal("a retried enrolment published a different encryption key")
	}
}

// Two connectors must not share a sealing key, and the sealing key must not be the signing key.
func TestEncryptionKeysAreDistinctPerIdentityAndPerPurpose(t *testing.T) {
	first, err := LoadOrCreateEnrollmentAttempt(t.TempDir(), "d0555ae5-d89f-41e8-ba24-31d238ffb8c8")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateEnrollmentAttempt(t.TempDir(), "d0555ae5-d89f-41e8-ba24-31d238ffb8c8")
	if err != nil {
		t.Fatal(err)
	}

	one, err := first.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	two, err := second.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if EncodePublicEncryption(one.PublicKey()) == EncodePublicEncryption(two.PublicKey()) {
		t.Fatal("two connectors derived the same sealing key")
	}
	// Domain separation, not the birational map: the sealing key must not be recoverable by
	// reading the signing key as if it were one.
	if EncodePublicEncryption(one.PublicKey()) == EncodePublic(first.PublicKey()) {
		t.Fatal("the sealing key is the signing key")
	}
	if bytes.Equal(one.Bytes(), first.PrivateKey().Seed()) {
		t.Fatal("the sealing private key is the identity seed itself")
	}
}

// A key the console cannot parse is a key nobody can seal to.
func TestAPublishedEncryptionKeyRoundTrips(t *testing.T) {
	attempt, err := LoadOrCreateEnrollmentAttempt(t.TempDir(), "d0555ae5-d89f-41e8-ba24-31d238ffb8c8")
	if err != nil {
		t.Fatal(err)
	}
	key, err := attempt.EncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePublicEncryption(EncodePublicEncryption(key.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(key.PublicKey()) {
		t.Fatal("the published key did not survive the protocol encoding")
	}
	if _, err := DecodePublicEncryption("not base64"); err == nil {
		t.Fatal("a malformed encryption key was accepted")
	}
}

package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentAttemptReusesOnePrivateKeyWithoutPersistingAToken(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "identity")
	organization := "d0555ae5-d89f-41e8-ba24-31d238ffb8c8"
	first, err := LoadOrCreateEnrollmentAttempt(directory, organization)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateEnrollmentAttempt(directory, organization)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || !bytes.Equal(first.PrivateKey(), second.PrivateKey()) {
		t.Fatal("an enrollment retry generated another identity")
	}
	raw, err := os.ReadFile(filepath.Join(directory, enrollmentAttemptFileName)) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("rtc_")) || bytes.Contains(raw, []byte("token")) {
		t.Fatal("pending enrollment state contains token material")
	}
	if err := CompleteEnrollmentAttempt(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, enrollmentAttemptFileName)); !os.IsNotExist(err) {
		t.Fatal("completed enrollment left pending retry material")
	}
}

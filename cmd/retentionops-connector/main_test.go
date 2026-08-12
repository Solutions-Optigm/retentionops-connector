package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPrivateTokenRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("rtc_secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateToken(path); err == nil {
		t.Fatal("a group- or world-readable enrollment token must be rejected")
	}
}

func TestReadPrivateTokenTrimsWithoutPrintingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("rtc_secret\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	token, err := readPrivateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "rtc_secret" {
		t.Fatalf("token = %q", token)
	}
}

func TestInitRejectsSecretBearingLegacyTokenFlag(t *testing.T) {
	var output strings.Builder
	err := runInitIO([]string{"--token", "rtc_secret"}, strings.NewReader(""), &output)
	if err == nil {
		t.Fatal("init accepted an unknown secret-bearing flag")
	}
	if strings.Contains(output.String(), "rtc_secret") {
		t.Fatal("secret was copied to init output")
	}
}

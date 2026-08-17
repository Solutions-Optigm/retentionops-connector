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

func TestSecretSetNeverTakesThePasswordAsAnArgument(t *testing.T) {
	// The console prints this command for an operator to paste. If a password could ride along in
	// argv it would end up in the process list, in shell history, and in the support ticket the
	// operator pastes the whole line into.
	for _, arguments := range [][]string{
		{"set", "hunter2"},
		{"set", "--role", "reader", "hunter2"},
	} {
		var output strings.Builder
		err := runSecret(arguments, os.Stdin, &output)
		if err == nil {
			t.Fatalf("%v was accepted", arguments)
		}
		if strings.Contains(output.String(), "hunter2") {
			t.Fatal("the value was copied to the output")
		}
	}
}

func TestSecretRequiresAKnownActionAndRole(t *testing.T) {
	var output strings.Builder
	if err := runSecret([]string{"rotate"}, os.Stdin, &output); err == nil {
		t.Fatal("an unknown secret action was accepted")
	}
	if err := runSecret([]string{"set", "--role", "superuser"}, os.Stdin, &output); err == nil {
		t.Fatal("an unknown role was accepted")
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

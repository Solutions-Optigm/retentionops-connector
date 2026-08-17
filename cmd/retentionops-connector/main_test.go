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
	_, _, err := runInitIO([]string{"--token", "rtc_secret"}, strings.NewReader(""), &output)
	if err == nil {
		t.Fatal("init accepted an unknown secret-bearing flag")
	}
	if strings.Contains(output.String(), "rtc_secret") {
		t.Fatal("secret was copied to init output")
	}
}

// `--install` is what lets the console print one command instead of two. The bundle directory it
// hands back is the one init actually chose, which is the point: the second command used to carry
// "$PWD/retentionops-connector-init" and was wrong for anybody who answered that question.
func TestInitReportsTheBundleOnlyWhenAskedToApplyIt(t *testing.T) {
	var output strings.Builder
	directory := filepath.Join(t.TempDir(), "elsewhere")
	arguments := []string{
		"--platform", "systemd",
		"--source", "4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52",
		"--organization", "d0555ae5-d89f-41e8-ba24-31d238ffb8c8",
		"--control-plane", "https://connector.retentionops.example",
	}
	answers := strings.Join([]string{directory, "", "", "", "file", "/etc/retentionops/secrets/reader-password", "public"}, "\n") + "\n"

	applied, repair, err := runInitIO(arguments, strings.NewReader(answers), &output)
	if err != nil {
		t.Fatal(err)
	}
	if applied != "" {
		t.Fatalf("init applied a bundle nobody asked it to apply: %q", applied)
	}

	applied, repair, err = runInitIO(append(arguments, "--install"), strings.NewReader(answers), &output)
	if err != nil {
		t.Fatal(err)
	}
	if applied != directory {
		t.Fatalf("applied = %q, want %q", applied, directory)
	}
	if repair {
		t.Fatal("files were replaceable without anybody asking")
	}

	// An installation that failed at enrolment has already written the runtime configuration, so
	// the corrected bundle differs from what is on disk. Without this the operator has to abandon
	// the one-command form to get past their own first attempt.
	if _, repair, err = runInitIO(append(arguments, "--install", "--repair"), strings.NewReader(answers), &output); err != nil {
		t.Fatal(err)
	}
	if !repair {
		t.Fatal("--repair did not reach the installer")
	}
}

package localsecret_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/localsecret"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

const source = "11111111-1111-4111-8111-111111111111"

func configuration(t *testing.T, provider, ref string) *config.Config {
	t.Helper()
	return &config.Config{
		Sources: map[string]*config.Source{
			source: {
				Type:     "postgresql",
				Reader:   config.Credential{Username: "reader", Password: config.SecretRef{Provider: provider, Ref: ref}},
				Executor: config.Credential{Username: "executor", Password: config.SecretRef{Provider: provider, Ref: ref + "-executor"}},
			},
		},
	}
}

func TestTheWrittenSecretIsWhatTheFileProviderWillAccept(t *testing.T) {
	target := filepath.Join(t.TempDir(), "secrets", "reader-password")

	path, err := localsecret.Set(configuration(t, "file", target), source, localsecret.Reader, strings.NewReader("hunter2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if path != target {
		t.Fatalf("path = %q", path)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != localsecret.Mode {
		t.Fatalf("mode = %#o", mode)
	}
	// The end-to-end property that matters: what was written is readable by the provider the
	// connector actually uses, and the trailing newline every editor adds is gone.
	value, err := secrets.Default().Resolve(t.Context(), "file", target)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "hunter2" {
		t.Fatalf("resolved %q", value)
	}
}

func TestAProviderThisHostDoesNotOwnIsRefused(t *testing.T) {
	for _, provider := range []string{"env", "aws-secrets-manager"} {
		_, err := localsecret.Set(configuration(t, provider, "RETENTIONOPS_READER"), source, localsecret.Reader, strings.NewReader("hunter2"))
		if !errors.Is(err, localsecret.ErrNotAFileProvider) {
			t.Fatalf("%s: err = %v", provider, err)
		}
	}
}

func TestAnEmptyOrOversizedSecretChangesNothing(t *testing.T) {
	target := filepath.Join(t.TempDir(), "reader-password")

	for name, value := range map[string]string{
		"empty":    "\n",
		"toolarge": strings.Repeat("x", localsecret.MaxSecretBytes+1),
	} {
		if _, err := localsecret.Set(configuration(t, "file", target), source, localsecret.Reader, strings.NewReader(value)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s left a file behind", name)
		}
	}
}

func TestASourceThisConnectorDoesNotDeclareIsRefused(t *testing.T) {
	target := filepath.Join(t.TempDir(), "reader-password")

	_, err := localsecret.Set(configuration(t, "file", target), "22222222-2222-4222-8222-222222222222", localsecret.Reader, strings.NewReader("hunter2"))
	if err == nil {
		t.Fatal("an undeclared source was accepted")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("a file was written for an undeclared source")
	}
}

func TestTheExecutorPasswordGoesToItsOwnFile(t *testing.T) {
	directory := t.TempDir()
	base := filepath.Join(directory, "reader-password")

	path, err := localsecret.Set(configuration(t, "file", base), source, localsecret.Executor, strings.NewReader("delete-me"))
	if err != nil {
		t.Fatal(err)
	}
	if path != base+"-executor" {
		t.Fatalf("path = %q", path)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatal("the reader password was overwritten by an executor write")
	}
}

func TestOnlySourceRefusesToGuessBetweenTwo(t *testing.T) {
	single := configuration(t, "file", filepath.Join(t.TempDir(), "reader-password"))
	id, err := localsecret.OnlySource(single)
	if err != nil || id != source {
		t.Fatalf("id = %q, err = %v", id, err)
	}

	single.Sources["33333333-3333-4333-8333-333333333333"] = &config.Source{Type: "postgresql"}
	if _, err := localsecret.OnlySource(single); err == nil {
		t.Fatal("a connector with two sources guessed one")
	}
}

package installer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/initializer"
)

const (
	testSource       = "4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52"
	testOrganization = "d0555ae5-d89f-41e8-ba24-31d238ffb8c8"
)

func TestInstallAppliesPrivateFilesWithoutPersistingSensitiveInputs(t *testing.T) {
	bundle, ca := bundleForTest(t)
	root := t.TempDir()
	var output strings.Builder
	err := Run(context.Background(), Options{
		Bundle: bundle, Root: root, SkipLiveChecks: true, Version: "test",
		Inputs:  Inputs{ReaderSecret: []byte("reader-secret"), Token: "rtc_one_time_value"},
		Prompts: Prompts{Confirm: func(string) (bool, error) { return true, nil }}, Out: &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, rooted(root, "/etc/retentionops/connector.yaml"), 0o640)
	assertFile(t, rooted(root, "/etc/retentionops/certs/postgres-ca.pem"), 0o644)
	assertFile(t, rooted(root, "/etc/retentionops/secrets/reader-password"), 0o400)
	state := read(t, rooted(root, "/var/lib/retentionops/install-state.json"))
	if strings.Contains(state, "reader-secret\"") || strings.Contains(state, "rtc_one_time_value") {
		t.Fatal("install state persisted a sensitive value")
	}
	if strings.Contains(output.String(), "reader-secret") || strings.Contains(output.String(), "rtc_one_time_value") {
		t.Fatal("installer printed a sensitive value")
	}
	if got := read(t, rooted(root, "/etc/retentionops/certs/postgres-ca.pem")); got != read(t, ca) {
		t.Fatal("installed CA differs from reviewed source")
	}
}

func TestInstallPreservesConflictingRuntimeFilesWithoutRepair(t *testing.T) {
	bundle, _ := bundleForTest(t)
	root := t.TempDir()
	options := Options{
		Bundle: bundle, Root: root, SkipLiveChecks: true, Version: "test",
		Inputs:  Inputs{ReaderSecret: []byte("reader-secret"), Token: "token"},
		Prompts: Prompts{Confirm: func(string) (bool, error) { return true, nil }},
	}
	if err := Run(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	configuration := rooted(root, "/etc/retentionops/connector.yaml")
	if err := os.WriteFile(configuration, []byte("operator change\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), options); err == nil || !strings.Contains(err.Error(), "--repair") {
		t.Fatalf("conflicting configuration was not preserved: %v", err)
	}
	if got := read(t, configuration); got != "operator change\n" {
		t.Fatal("conflicting configuration was overwritten")
	}
}

func TestBundleDigestMismatchStopsBeforeInstallation(t *testing.T) {
	bundle, _ := bundleForTest(t)
	if err := os.WriteFile(filepath.Join(bundle, "roles.sql"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Options{Bundle: bundle, Root: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered bundle was accepted: %v", err)
	}
}

func TestInstallNeverOverwritesAnUnusableExistingIdentity(t *testing.T) {
	bundle, _ := bundleForTest(t)
	root := t.TempDir()
	identityPath := rooted(root, "/var/lib/retentionops/identity/identity.json")
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, []byte("operator identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Options{
		Bundle: bundle, Root: root, SkipLiveChecks: true, Version: "test",
		Inputs:  Inputs{ReaderSecret: []byte("reader-secret"), Token: "token"},
		Prompts: Prompts{Confirm: func(string) (bool, error) { return true, nil }},
	})
	if err == nil || !strings.Contains(err.Error(), "preserved") {
		t.Fatalf("unusable identity was not rejected safely: %v", err)
	}
	if got := read(t, identityPath); got != "operator identity" {
		t.Fatal("existing identity was overwritten")
	}
}

func bundleForTest(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	ca := filepath.Join(root, "postgres-ca.pem")
	writeTestCA(t, ca)
	bundle := filepath.Join(root, "bundle")
	answers := initializer.Answers{
		Version: initializer.AnswersVersion, Platform: initializer.PlatformSystemd,
		OutputDirectory: bundle, OrganizationID: testOrganization, SourceID: testSource,
		ControlPlane: initializer.ControlPlane{URL: "https://connector.retentionops.example"},
		Source: initializer.Source{
			Host: "127.0.0.1", Port: 5432, Database: "retentionops_test",
			TLSCASourceFile: ca, TLSCAFile: "/etc/retentionops/certs/postgres-ca.pem",
			Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
				Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
			}},
			AllowedSchemas: []string{"public"},
		},
	}
	if err := initializer.Generate(answers); err != nil {
		t.Fatal(err)
	}
	return bundle, ca
}

func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("%s mode %#o, want %#o", path, info.Mode().Perm(), mode)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Without this the connector reaches a private control plane only on a host whose trust store
// somebody edited by hand — state no later command can see, verify or reproduce elsewhere, and
// whose absence surfaces at enrolment as "certificate signed by unknown authority".
func TestInstallPlacesThePrivateControlPlaneCertificate(t *testing.T) {
	root := t.TempDir()
	postgresCA := filepath.Join(root, "postgres-ca.pem")
	controlPlaneCA := filepath.Join(root, "control-plane-ca.pem")
	writeTestCA(t, postgresCA)
	writeTestCA(t, controlPlaneCA)
	bundle := filepath.Join(root, "bundle")
	answers := initializer.Answers{
		Version: initializer.AnswersVersion, Platform: initializer.PlatformSystemd,
		OutputDirectory: bundle, OrganizationID: testOrganization, SourceID: testSource,
		ControlPlane: initializer.ControlPlane{
			URL: "https://connector.retentionops.example", CASourceFile: controlPlaneCA,
		},
		Source: initializer.Source{
			Host: "127.0.0.1", Port: 5432, Database: "retentionops_test",
			TLSCASourceFile: postgresCA, TLSCAFile: "/etc/retentionops/certs/postgres-ca.pem",
			Reader: config.Credential{Username: "retentionops_reader", Password: config.SecretRef{
				Provider: "file", Ref: "/etc/retentionops/secrets/reader-password",
			}},
			AllowedSchemas: []string{"public"},
		},
	}
	if err := initializer.Generate(answers); err != nil {
		t.Fatal(err)
	}

	installRoot := t.TempDir()
	err := Run(context.Background(), Options{
		Bundle: bundle, Root: installRoot, SkipLiveChecks: true, Version: "test",
		Inputs:  Inputs{ReaderSecret: []byte("reader-secret"), Token: "rtc_one_time_value"},
		Prompts: Prompts{Confirm: func(string) (bool, error) { return true, nil }},
		Out:     &strings.Builder{},
	})
	if err != nil {
		t.Fatal(err)
	}

	installed := rooted(installRoot, "/etc/retentionops/certs/control-plane-ca.pem")
	assertFile(t, installed, 0o644)
	if read(t, installed) != read(t, controlPlaneCA) {
		t.Fatal("installed control-plane CA differs from the reviewed source")
	}
	// The two certificates must not be confused for one another: the connector verifies a
	// different peer with each, and swapping them fails in a way that reads as a network problem.
	if read(t, installed) == read(t, rooted(installRoot, "/etc/retentionops/certs/postgres-ca.pem")) {
		t.Fatal("the control-plane and PostgreSQL certificates were installed from the same source")
	}
}

// The hosted deployment supplies no certificate and must install none: a stray file would be a
// pinned trust anchor nobody reviewed and nobody rotates.
func TestInstallWritesNoControlPlaneCertificateWhenNoneWasSupplied(t *testing.T) {
	bundle, _ := bundleForTest(t)
	root := t.TempDir()
	err := Run(context.Background(), Options{
		Bundle: bundle, Root: root, SkipLiveChecks: true, Version: "test",
		Inputs:  Inputs{ReaderSecret: []byte("reader-secret"), Token: "rtc_one_time_value"},
		Prompts: Prompts{Confirm: func(string) (bool, error) { return true, nil }},
		Out:     &strings.Builder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rooted(root, "/etc/retentionops/certs/control-plane-ca.pem")); !os.IsNotExist(err) {
		t.Fatal("install pinned a control-plane CA that the bundle never declared")
	}
}

// Package installer applies a reviewed init bundle without turning the connector into a command
// runner. Database SQL and process supervision remain explicit operator actions; all connector
// checks, enrollment and private-file handling happen through the same Go paths used at runtime.
package installer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/solutions-optigm/retentionops-connector/adapters/postgres"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/doctor"
	"github.com/solutions-optigm/retentionops-connector/internal/enrollment"
	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	"github.com/solutions-optigm/retentionops-connector/internal/initializer"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

const stateVersion = 1

// Inputs contains sensitive values supplied through private files or masked prompts. Callers
// must never render this structure or persist it in the install state.
type Inputs struct {
	ReaderSecret []byte
	Token        string
	Organization string
	CASourceFile string
}

// Prompts supplies the few human decisions that cannot be inferred safely.
type Prompts struct {
	Secret  func(label string) ([]byte, error)
	Token   func() (string, error)
	Confirm func(question string) (bool, error)
}

// Options controls one idempotent application of a bundle. Root exists for filesystem tests and
// recovery tooling; production uses "/".
type Options struct {
	Bundle              string
	Root                string
	Repair              bool
	NonInteractive      bool
	SkipLiveChecks      bool
	DatabaseRoleApplied bool
	Version             string
	Inputs              Inputs
	Prompts             Prompts
	Out                 io.Writer
}

type installState struct {
	Version   int       `json:"version"`
	Bundle    string    `json:"bundle"`
	Completed []string  `json:"completed"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Run applies or resumes a bundle. It never invokes a shell, psql, systemctl or Docker.
func Run(ctx context.Context, options Options) error {
	if options.Root == "" {
		options.Root = "/"
	}
	if options.Out == nil {
		options.Out = io.Discard
	}
	manifest, bundle, err := initializer.LoadBundle(options.Bundle)
	if err != nil {
		return err
	}
	configuration, err := config.Load(filepath.Join(bundle, "connector.yaml"))
	if err != nil {
		return err
	}
	if options.Root == "/" && manifest.Platform == initializer.PlatformSystemd && os.Geteuid() != 0 {
		return errors.New("install: systemd installation must run as root")
	}
	if err := preflight(options, manifest, bundle); err != nil {
		return err
	}

	statePath := rooted(options.Root, "/var/lib/retentionops/install-state.json")
	if manifest.Platform == initializer.PlatformCompose {
		statePath = filepath.Join(bundle, "runtime/install-state.json")
	}
	state, err := loadState(statePath, bundle)
	if err != nil {
		return err
	}
	complete := func(stage string) error {
		if !contains(state.Completed, stage) {
			state.Completed = append(state.Completed, stage)
		}
		state.UpdatedAt = time.Now().UTC().Truncate(time.Second)
		return saveState(statePath, state)
	}

	if err := prepareRuntime(options, manifest, bundle); err != nil {
		return err
	}
	if err := complete("runtime-prepared"); err != nil {
		return err
	}

	// A source the console configures has no database name yet, so there is no SQL to hand a DBA
	// and nothing to confirm. The roles are created after the configuration arrives, from
	// `retentionops-connector source roles`, which can finally name them. Asking here would be
	// asking somebody to confirm they ran a script that does not exist.
	pending := isPending(configuration, manifest.SourceID)
	if pending {
		fmt.Fprintf(options.Out, "\nThis connector is configured from the RetentionOps console. "+
			"Enrol now; the database, its roles and the connection test all follow from there.\n")
	} else {
		if err := confirmDatabaseRole(options, manifest, bundle, state, complete); err != nil {
			return err
		}
	}

	runtimeConfiguration, secretPath, identityDirectory, err := runtimeView(options, manifest, bundle, configuration)
	if err != nil {
		return err
	}
	if err := ensureReaderSecret(options, secretPath, pending); err != nil {
		return err
	}
	if manifest.Platform == initializer.PlatformSystemd {
		if err := protectSystemdOwnership(options.Root, manifest, secretPath); err != nil {
			return err
		}
	}
	if manifest.Platform == initializer.PlatformCompose {
		if err := protectComposeOwnership(bundle); err != nil {
			return err
		}
	}
	if err := complete("reader-secret-installed"); err != nil {
		return err
	}

	// Nothing to test against until the console has said where the database is. The test is not
	// skipped so much as moved: it is the console's step 5, run by this same connector, and its
	// result is signed rather than printed here.
	if !options.SkipLiveChecks && !pending {
		if err := checkSource(ctx, runtimeConfiguration, manifest.SourceID); err != nil {
			return err
		}
		if err := complete("source-validated"); err != nil {
			return err
		}
	}
	return finishInstall(ctx, options, manifest, bundle, state, complete, runtimeConfiguration, identityDirectory)
}

func isPending(configuration *config.Config, sourceID string) bool {
	source, known := configuration.Source(sourceID)
	return known && source.Pending()
}

func confirmDatabaseRole(options Options, manifest initializer.BundleManifest, bundle string, state *installState, complete func(string) error) error {
	dbaCommand := databaseCommand(manifest, filepath.Join(bundle, "roles.sql"))
	fmt.Fprintf(options.Out, "\nApply the reviewed reader-role SQL as a PostgreSQL administrator:\n  %s\n", dbaCommand)
	if !contains(state.Completed, "database-role-confirmed") {
		if options.DatabaseRoleApplied {
			if err := complete("database-role-confirmed"); err != nil {
				return err
			}
		} else {
			if options.NonInteractive {
				return errors.New("install: database role confirmation is required before unattended installation can continue")
			}
			if options.Prompts.Confirm == nil {
				return errors.New("install: no database-role confirmation prompt is available")
			}
			confirmed, promptErr := options.Prompts.Confirm("Has the reviewed roles.sql completed successfully?")
			if promptErr != nil {
				return promptErr
			}
			if !confirmed {
				return errors.New("install: database role was not confirmed; resume after the DBA applies roles.sql")
			}
			if err := complete("database-role-confirmed"); err != nil {
				return err
			}
		}
	}
	return nil
}

// finishInstall enrols the connector and verifies the installation it can verify.
//
// Split out because the steps before it now differ: a source the console configures has no
// database to test and no roles to confirm, while everything from here on — identity, enrolment,
// doctor, activation — is the same either way.
func finishInstall(
	ctx context.Context,
	options Options,
	manifest initializer.BundleManifest,
	bundle string,
	state *installState,
	complete func(string) error,
	runtimeConfiguration *config.Config,
	identityDirectory string,
) error {
	organization := manifest.OrganizationID
	if organization == "" {
		organization = options.Inputs.Organization
	}
	if organization == "" {
		return errors.New("install: organization UUID is absent from this legacy bundle; provide --organization")
	}
	existingIdentity, identityErr := identity.Load(identityDirectory)
	if identityErr == nil && existingIdentity.OrganizationID != organization {
		return fmt.Errorf("install: existing identity belongs to organization %s; it was preserved", existingIdentity.OrganizationID)
	}
	if identityErr != nil {
		identityPath := filepath.Join(identityDirectory, identity.FileName)
		if _, statErr := os.Stat(identityPath); statErr == nil {
			return fmt.Errorf("install: existing identity is not usable and was preserved: %w", identityErr)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("install: inspect existing identity: %w", statErr)
		}
		token := strings.TrimSpace(options.Inputs.Token)
		if token == "" {
			if options.NonInteractive || options.Prompts.Token == nil {
				return errors.New("install: enrollment token is required through --token-file")
			}
			prompted, err := options.Prompts.Token()
			if err != nil {
				return err
			}
			token = prompted
		}
		if token == "" {
			return errors.New("install: enrollment token is empty")
		}
		if options.SkipLiveChecks {
			fmt.Fprintln(options.Out, "Enrollment skipped by the filesystem verification harness.")
		} else if _, err := enrollment.Run(ctx, enrollment.Request{
			ControlPlaneURL: manifest.ControlPlaneURL, OrganizationID: organization,
			Token: token, Version: options.Version, CAFile: runtimeConfiguration.ControlPlane.CAFile,
			Directory: identityDirectory,
		}); err != nil {
			return err
		}
	}
	if manifest.Platform == initializer.PlatformSystemd {
		if err := protectSystemdIdentity(options.Root, identityDirectory); err != nil {
			return err
		}
	} else if err := protectComposeOwnership(bundle); err != nil {
		return err
	}
	if !options.SkipLiveChecks {
		if err := complete("enrolled"); err != nil {
			return err
		}
	}

	if !options.SkipLiveChecks {
		id, err := identity.Load(identityDirectory)
		if err != nil {
			return err
		}
		report := doctor.Run(ctx, runtimeConfiguration, id, secrets.Default())
		report.Write(options.Out)
		if !report.Healthy() {
			return errors.New("install: doctor reported at least one failed check")
		}
	}
	if !options.SkipLiveChecks {
		if err := complete("doctor-passed"); err != nil {
			return err
		}
	}

	activation := "sudo systemctl enable --now retentionops-connector"
	if manifest.Platform == initializer.PlatformCompose {
		activation = "docker compose -f " + filepath.Join(bundle, "compose.yaml") + " up -d"
	}
	fmt.Fprintf(options.Out, "\nInstallation checks passed. Execution remains disabled locally.\nActivate supervision explicitly:\n  %s\n", activation)
	if options.SkipLiveChecks {
		return nil
	}
	return complete("activation-pending")
}

func prepareRuntime(options Options, manifest initializer.BundleManifest, bundle string) error {
	if manifest.Platform == initializer.PlatformSystemd {
		paths := []struct {
			path string
			mode fs.FileMode
		}{{"/etc/retentionops", 0o750}, {"/etc/retentionops/certs", 0o750}, {"/etc/retentionops/secrets", 0o750},
			{"/var/lib/retentionops/identity", 0o700}, {"/var/lib/retentionops/state", 0o700}}
		for _, candidate := range paths {
			if err := os.MkdirAll(rooted(options.Root, candidate.path), candidate.mode); err != nil {
				return fmt.Errorf("install: create %s: %w", candidate.path, err)
			}
			if err := os.Chmod(rooted(options.Root, candidate.path), candidate.mode); err != nil {
				return fmt.Errorf("install: protect %s: %w", candidate.path, err)
			}
		}
		if err := installFile(filepath.Join(bundle, "connector.yaml"), rooted(options.Root, manifest.RuntimeConfig), 0o640, options.Repair); err != nil {
			return err
		}
		caSource := manifest.PostgreSQL.CASourceFile
		if options.Inputs.CASourceFile != "" {
			caSource = options.Inputs.CASourceFile
		}
		// No certificate is a complete answer: the connector then verifies the database against
		// this host's own trust store, which is how every other TLS client here works. A bundle
		// that names one must still produce it, or `verify-full` would silently fall back to
		// different roots than the operator chose.
		if manifest.PostgreSQL.CARuntimeFile != "" {
			caTarget := rooted(options.Root, manifest.PostgreSQL.CARuntimeFile)
			if caSource == "" {
				if _, err := os.Stat(caTarget); err != nil {
					return errors.New("install: this bundle expects a PostgreSQL CA; provide --ca-file")
				}
			} else if err := validateAndInstallCA(caSource, caTarget, options.Repair); err != nil {
				return err
			}
		}
		if err := installControlPlaneCA(manifest, options.Root, options.Repair); err != nil {
			return err
		}
		return chownRuntime(options.Root)
	}

	for _, directory := range []string{"runtime/certs", "runtime/secrets", "runtime/identity", "runtime/state"} {
		path := filepath.Join(bundle, directory)
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("install: create %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("install: protect %s: %w", path, err)
		}
	}
	caSource := manifest.PostgreSQL.CASourceFile
	if options.Inputs.CASourceFile != "" {
		caSource = options.Inputs.CASourceFile
	}
	if caSource == "" && manifest.PostgreSQL.CARuntimeFile != "" {
		return errors.New("install: this bundle expects a PostgreSQL CA; provide --ca-file")
	}
	if caSource != "" {
		if err := validateAndInstallCA(caSource, filepath.Join(bundle, "runtime/certs/postgres-ca.pem"), options.Repair); err != nil {
			return err
		}
	}
	// compose.yaml mounts this path from the bundle, so it lands beside the PostgreSQL CA rather
	// than at the absolute runtime path the container will see.
	return installControlPlaneCAFrom(manifest, filepath.Join(bundle, "runtime/certs/control-plane-ca.pem"), options.Repair)
}

// installControlPlaneCA is a no-op for a publicly trusted control plane, which records no
// certificate and verifies against the host's roots.
func installControlPlaneCA(manifest initializer.BundleManifest, root string, repair bool) error {
	if manifest.ControlPlaneCARuntimeFile == "" {
		return nil
	}
	return installControlPlaneCAFrom(manifest, rooted(root, manifest.ControlPlaneCARuntimeFile), repair)
}

func installControlPlaneCAFrom(manifest initializer.BundleManifest, target string, repair bool) error {
	source := manifest.ControlPlaneCASourceFile
	if source == "" {
		return nil
	}
	raw, err := os.ReadFile(source) //nolint:gosec // explicit local CA path
	if err != nil {
		return fmt.Errorf("install: read control-plane CA %s: %w", source, err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(raw) {
		return fmt.Errorf("install: control-plane CA %s contains no PEM certificate", source)
	}
	return installBytes(raw, target, 0o644, repair)
}

func preflight(options Options, manifest initializer.BundleManifest, bundle string) error {
	probe := bundle
	if manifest.Platform == initializer.PlatformSystemd {
		probe = options.Root
		if options.Root == "/" {
			if _, err := os.Stat("/usr/lib/systemd/system/retentionops-connector.service"); err != nil {
				return errors.New("install: hardened systemd unit is missing; install the signed Debian package first")
			}
		}
	} else if findExecutable("docker") == "" {
		return errors.New("install: Docker is absent from PATH")
	}
	var statistics syscall.Statfs_t
	if err := syscall.Statfs(probe, &statistics); err != nil {
		return fmt.Errorf("install: inspect available disk space: %w", err)
	}
	available := statistics.Bavail * uint64(statistics.Bsize)
	if available < 64*1024*1024 {
		return fmt.Errorf("install: only %d bytes are available; at least 64 MiB is required", available)
	}
	return nil
}

func findExecutable(name string) string {
	for _, directory := range filepath.SplitList(os.Getenv("PATH")) {
		candidate := filepath.Join(directory, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

func runtimeView(options Options, manifest initializer.BundleManifest, bundle string, configuration *config.Config) (*config.Config, string, string, error) {
	source, ok := configuration.Source(manifest.SourceID)
	if !ok {
		return nil, "", "", fmt.Errorf("install: source %s is absent from connector.yaml", manifest.SourceID)
	}
	if manifest.Platform == initializer.PlatformSystemd {
		if options.Root != "/" {
			if source.TLS.CAFile != "" {
				source.TLS.CAFile = rooted(options.Root, source.TLS.CAFile)
			}
			source.Reader.Password.Ref = rooted(options.Root, source.Reader.Password.Ref)
			configuration.Identity.Directory = rooted(options.Root, configuration.Identity.Directory)
			configuration.State.Directory = rooted(options.Root, configuration.State.Directory)
		}
		return configuration, source.Reader.Password.Ref, configuration.Identity.Directory, nil
	}
	// Left empty when the bundle carries no certificate: the container then verifies against the
	// roots in the image, and pointing at a file that was never installed would fail every
	// connection with a message about a missing path rather than about trust.
	if source.TLS.CAFile != "" {
		source.TLS.CAFile = filepath.Join(bundle, "runtime/certs/postgres-ca.pem")
	}
	source.Reader.Password.Ref = filepath.Join(bundle, "runtime/secrets/reader-password")
	configuration.Identity.Directory = filepath.Join(bundle, "runtime/identity")
	configuration.State.Directory = filepath.Join(bundle, "runtime/state")
	return configuration, source.Reader.Password.Ref, configuration.Identity.Directory, nil
}

func ensureReaderSecret(options Options, target string, optional bool) error {
	if existing, err := os.ReadFile(target); err == nil && len(bytes.TrimSpace(existing)) > 0 { //nolint:gosec // local credential target
		if info, statErr := os.Stat(target); statErr != nil || info.Mode().Perm()&0o044 != 0 {
			return fmt.Errorf("install: existing reader secret is not private")
		}
		return nil
	}
	secret := bytes.TrimRight(options.Inputs.ReaderSecret, "\r\n")
	if len(secret) == 0 && optional {
		// Nobody has named the role this password belongs to yet, so demanding it here would be
		// asking for the password of a role the operator has not chosen. `secret set` writes it
		// after the console does, and the console waits for a signed test rather than a promise.
		return nil
	}
	if len(secret) == 0 {
		if options.NonInteractive || options.Prompts.Secret == nil {
			return errors.New("install: reader secret is required through --reader-secret-file")
		}
		var err error
		secret, err = options.Prompts.Secret("PostgreSQL reader password")
		if err != nil {
			return err
		}
		secret = bytes.TrimRight(secret, "\r\n")
	}
	if len(secret) == 0 {
		return errors.New("install: reader secret is empty")
	}
	if len(secret) > 64*1024 {
		return errors.New("install: reader secret is unexpectedly large")
	}
	return atomicWrite(target, secret, 0o400)
}

func checkSource(ctx context.Context, configuration *config.Config, sourceID string) error {
	source, ok := configuration.Source(sourceID)
	if !ok {
		return fmt.Errorf("install: source %s is absent", sourceID)
	}
	adapter := postgres.New(sourceID, source, secrets.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	statistics, err := adapter.TestConnection(ctx)
	if err != nil {
		return fmt.Errorf("install: source test: %w", err)
	}
	if !statistics.ReaderValidated {
		return errors.New("install: PostgreSQL reader identity was not validated")
	}
	if _, err := adapter.Discover(ctx); err != nil {
		return fmt.Errorf("install: source discovery: %w", err)
	}
	return nil
}

func databaseCommand(manifest initializer.BundleManifest, rolesPath string) string {
	quotedFile := shellQuote(rolesPath)
	if manifest.PostgreSQL.Host == "127.0.0.1" || manifest.PostgreSQL.Host == "localhost" {
		return fmt.Sprintf("sudo -u postgres psql --dbname %s --file %s", shellQuote(manifest.PostgreSQL.Database), quotedFile)
	}
	return fmt.Sprintf("psql --host %s --port %d --dbname %s --file %s",
		shellQuote(manifest.PostgreSQL.Host), manifest.PostgreSQL.Port,
		shellQuote(manifest.PostgreSQL.Database), quotedFile)
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func validateAndInstallCA(source, target string, repair bool) error {
	raw, err := os.ReadFile(source) //nolint:gosec // explicit local CA path
	if err != nil {
		return fmt.Errorf("install: read PostgreSQL CA %s: %w", source, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return fmt.Errorf("install: PostgreSQL CA %s contains no PEM certificate", source)
	}
	return installBytes(raw, target, 0o644, repair)
}

func installFile(source, target string, mode fs.FileMode, repair bool) error {
	raw, err := os.ReadFile(source) //nolint:gosec // bundle artifact already verified
	if err != nil {
		return fmt.Errorf("install: read %s: %w", source, err)
	}
	return installBytes(raw, target, mode, repair)
}

func installBytes(content []byte, target string, mode fs.FileMode, repair bool) error {
	if existing, err := os.ReadFile(target); err == nil { //nolint:gosec // explicit runtime target
		if bytes.Equal(existing, content) {
			return os.Chmod(target, mode)
		}
		if !repair {
			return fmt.Errorf("install: %s already exists with different content; rerun with --repair after review", target)
		}
		backup := target + ".backup-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(target, backup); err != nil {
			return fmt.Errorf("install: back up %s: %w", target, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("install: inspect %s: %w", target, err)
	}
	return atomicWrite(target, content, mode)
}

func atomicWrite(path string, content []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("install: create %s: %w", filepath.Dir(path), err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".retentionops-install-*")
	if err != nil {
		return fmt.Errorf("install: stage %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("install: write %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install: install %s: %w", path, err)
	}
	return os.Chmod(path, mode)
}

func loadState(path, bundle string) (*installState, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // local state path
	if errors.Is(err, os.ErrNotExist) {
		return &installState{Version: stateVersion, Bundle: bundle, Completed: []string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("install: read state: %w", err)
	}
	var state installState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("install: parse state: %w", err)
	}
	if state.Version != stateVersion || state.Bundle != bundle {
		return nil, errors.New("install: existing install state belongs to another bundle or version")
	}
	return &state, nil
}

func saveState(path string, state *installState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'), 0o600)
}

func rooted(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func chownRuntime(root string) error {
	if root != "/" || os.Geteuid() != 0 {
		return nil
	}
	account, err := user.Lookup("retentionops")
	if err != nil {
		return errors.New("install: retentionops service account is missing; install the signed Debian package first")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	for _, path := range []string{"/var/lib/retentionops", "/var/lib/retentionops/identity", "/var/lib/retentionops/state"} {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("install: own %s: %w", path, err)
		}
	}
	return nil
}

func protectSystemdOwnership(root string, manifest initializer.BundleManifest, secretPath string) error {
	if root != "/" || os.Geteuid() != 0 {
		return nil
	}
	account, err := user.Lookup("retentionops")
	if err != nil {
		return errors.New("install: retentionops service account is missing; install the signed Debian package first")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	for _, path := range []string{"/etc/retentionops", "/etc/retentionops/certs", "/etc/retentionops/secrets", manifest.RuntimeConfig, manifest.PostgreSQL.CARuntimeFile} {
		if err := os.Chown(path, 0, gid); err != nil {
			return fmt.Errorf("install: own %s: %w", path, err)
		}
	}
	if err := os.Chown(secretPath, uid, gid); err != nil {
		return fmt.Errorf("install: own %s: %w", secretPath, err)
	}
	return os.Chmod(secretPath, 0o400)
}

func protectSystemdIdentity(root, directory string) error {
	if root != "/" || os.Geteuid() != 0 {
		return nil
	}
	account, err := user.Lookup("retentionops")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chown(path, uid, gid)
	})
}

func protectComposeOwnership(bundle string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return filepath.WalkDir(filepath.Join(bundle, "runtime"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chown(path, 65532, 65532)
	})
}

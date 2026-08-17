// Package localsecret writes a database password into the file the source's own configuration
// names, on the host that owns it.
//
// This exists because of what RetentionOps deliberately cannot do. A console can send where to
// connect and as which roles; it can never send the password, so the last step of an installation
// always happens on the customer's machine. That step used to be a paragraph of `install`,
// `chown` and `chmod` copied out of a manual, where every mistake — a trailing newline, a
// group-readable file, ownership left with root — produces an authentication failure that looks
// nothing like its cause.
//
// The whole package is one command's worth of care: the value arrives on a reader (a masked
// prompt or a private file), never in an argument, and lands with the same durability, mode and
// ownership `install` gives it.
package localsecret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
)

// Role names the identity whose password is being written.
type Role string

const (
	// Reader plans and inspects. It is the one every installation needs.
	Reader Role = "reader"
	// Executor deletes. A connector that only plans never resolves it, which is why a
	// planning-path flaw cannot reach delete rights.
	Executor Role = "executor"
)

// MaxSecretBytes bounds what will be accepted as a password.
//
// Not a security control — it catches the operator who pipes the wrong file into the command and
// would otherwise write a certificate, a core dump or a database into their secrets directory.
const MaxSecretBytes = 64 * 1024

// ErrNotAFileProvider is returned for a source whose password is not read from a file.
//
// `env` and `aws-secrets-manager` are resolved by something this connector does not own: an
// environment the service manager supplies, or an account in someone's cloud. Writing a file
// beside them would leave two answers to the same question, with the connector using the one the
// operator was not looking at.
var ErrNotAFileProvider = errors.New("localsecret: this source resolves its password through a provider only its own system can change")

// Set writes one role's password for one source and reports where it landed.
//
// Atomic, because a half-written credential file is an outage: staged beside the target, synced,
// then renamed. Mode 0400 and owned by the service account, which is what the file provider
// requires — it refuses anything a group or other user can read, so a secret written with a
// friendlier mode would be rejected at the next connection rather than here.
func Set(configuration *config.Config, sourceID string, role Role, value io.Reader) (string, error) {
	source, known := configuration.Source(sourceID)
	if !known || source == nil {
		return "", fmt.Errorf("localsecret: source %s is not declared in this connector's configuration", sourceID)
	}
	credential := source.Reader
	if role == Executor {
		credential = source.Executor
	}
	if credential.Password.Provider != "file" {
		return "", fmt.Errorf("%w: %s", ErrNotAFileProvider, credential.Password.Provider)
	}
	if credential.Password.Ref == "" {
		return "", fmt.Errorf("localsecret: the %s identity of source %s names no password file", role, sourceID)
	}

	secret, err := read(value)
	if err != nil {
		return "", err
	}
	if err := write(credential.Password.Ref, secret); err != nil {
		return "", err
	}
	return credential.Password.Ref, nil
}

// OnlySource returns the single declared source, so the common installation needs no identifier.
//
// Most hosts run one connector against one database, and asking that operator to paste a UUID is
// asking them to prove they read the console carefully. An ambiguous answer is an error rather
// than a guess: writing the wrong database's password is not something to recover from later.
func OnlySource(configuration *config.Config) (string, error) {
	switch len(configuration.Sources) {
	case 0:
		return "", errors.New("localsecret: this connector declares no source")
	case 1:
		for id := range configuration.Sources {
			return id, nil
		}
	}
	return "", errors.New("localsecret: this connector declares several sources; name one with --source")
}

func read(value io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(value, MaxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("localsecret: read the password: %w", err)
	}
	if len(raw) > MaxSecretBytes {
		return nil, errors.New("localsecret: that is far larger than a password; check what was piped in")
	}
	// Trimmed for the same reason the file provider trims on the way out: every editor and every
	// `echo` adds a newline, and a password with an invisible one authenticates nowhere.
	secret := bytes.TrimRight(raw, "\r\n")
	if len(secret) == 0 {
		return nil, errors.New("localsecret: the password is empty")
	}
	return secret, nil
}

func write(path string, secret []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("localsecret: create %s: %w", directory, err)
	}
	staged, err := os.CreateTemp(directory, ".retentionops-secret-*")
	if err != nil {
		return fmt.Errorf("localsecret: stage %s: %w", path, err)
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)

	if err := staged.Chmod(0o400); err != nil {
		_ = staged.Close()
		return err
	}
	if _, err := staged.Write(secret); err != nil {
		_ = staged.Close()
		return fmt.Errorf("localsecret: write %s: %w", path, err)
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := own(stagedPath); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return fmt.Errorf("localsecret: install %s: %w", path, err)
	}
	return syncDirectory(directory)
}

// own hands the file to the service account when the command runs as root.
//
// Skipped when it is not: a container image or a development checkout runs the connector as the
// same user that writes the file, and there is no account to look up.
func own(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	account, err := user.Lookup("retentionops")
	if err != nil {
		// Root without the packaged account is a manual installation. The file is already
		// unreadable to anyone but its owner, which is the property that matters.
		return nil //nolint:nilerr // absence of the packaged account is not a failure here
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("localsecret: own %s: %w", path, err)
	}
	return nil
}

// syncDirectory makes the rename itself durable.
//
// The rename is atomic for a reader immediately, but the directory entry is not on disk until the
// directory is synced. A power loss in between leaves a connector that starts with no credential
// and an operator certain they set one.
func syncDirectory(path string) error {
	handle, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("localsecret: open %s: %w", path, err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("localsecret: sync %s: %w", path, err)
	}
	return nil
}

// Mode is what a correctly written credential file looks like, exported for tests and doctor.
const Mode fs.FileMode = 0o400

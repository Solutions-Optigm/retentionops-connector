// Package jobs turns a document that arrived over the network into a job this connector is
// willing to run — or into a stable refusal code.
//
// The order of the checks is part of the design. Cheap, local, non-cryptographic refusals come
// first, then the signature, then the replay ledger, and only then does the caller consult the
// local safety policy. Nothing touches a database until every one of them has passed.
package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ErrReplayed is returned when a nonce has already been consumed.
var ErrReplayed = errors.New("jobs: nonce already used")

// ReplayLedger remembers which job nonces this connector has already accepted.
//
// It is a directory of empty files named by the digest of the nonce, created with O_EXCL. That
// makes "have I seen this before" a single atomic filesystem operation that is correct even if
// two connector processes are accidentally started against the same state directory — a
// scenario an in-memory set would get silently wrong.
type ReplayLedger struct {
	directory string
	retention time.Duration
}

// NewReplayLedger prepares the ledger directory.
//
// retention should exceed the longest job lifetime the control plane issues. Entries are pruned
// after it, because a nonce whose job could no longer be accepted anyway is dead weight.
func NewReplayLedger(directory string, retention time.Duration) (*ReplayLedger, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("jobs: create replay ledger %s: %w", directory, err)
	}
	return &ReplayLedger{directory: directory, retention: retention}, nil
}

// Consume records a nonce as used, or reports ErrReplayed if it already was.
//
// It is called during verification, before any work starts, and never rolled back. A connector
// that crashes between consuming a nonce and executing the job loses that job: the control plane
// times it out and re-issues a fresh one. That is the correct trade for a destructive operation —
// the failure mode is "did not run", not "ran twice".
func (l *ReplayLedger) Consume(nonce string) error {
	path := l.path(nonce)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrReplayed
		}
		return fmt.Errorf("jobs: record nonce: %w", err)
	}
	return file.Close()
}

// Prune removes entries older than the retention window.
func (l *ReplayLedger) Prune(now time.Time) (int, error) {
	entries, err := os.ReadDir(l.directory)
	if err != nil {
		return 0, fmt.Errorf("jobs: read replay ledger: %w", err)
	}
	removed := 0
	cutoff := now.Add(-l.retention)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(l.directory, entry.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// path names the ledger entry by digest rather than by the nonce itself.
//
// Nonce characters are filesystem-safe, but a case-insensitive filesystem — macOS by default —
// would treat two distinct nonces differing only in case as the same file and silently refuse a
// legitimate job. Hashing removes the filesystem's opinion from the equation.
func (l *ReplayLedger) path(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return filepath.Join(l.directory, hex.EncodeToString(sum[:]))
}

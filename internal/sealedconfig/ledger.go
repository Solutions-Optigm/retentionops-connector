package sealedconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Outcomes a connector reports back. Codes, never messages: a connector's own error text can name
// a host, and nothing that reaches the control plane may.
const (
	OutcomeApplied           = "APPLIED"
	OutcomeAlreadyApplied    = "ALREADY_APPLIED"
	OutcomeRefusedUnreadable = "REFUSED_UNREADABLE"
	OutcomeRefusedExpired    = "REFUSED_EXPIRED"
	OutcomeRefusedInvalid    = "REFUSED_INVALID"
)

// Ledger remembers which envelopes this connector has already dealt with, and what came of each.
//
// Durable rather than in-memory, because delivery is at-least-once by design: the control plane
// redelivers an envelope until it is acknowledged, so a lost acknowledgement or a restart between
// the two brings the same envelope back. Remembering in memory would mean a connector that
// restarts re-applies, which is the exact failure the envelope id exists to prevent.
//
// One file per envelope, named by digest, holding the outcome. Written with O_EXCL so the claim
// is a single atomic filesystem operation, correct even if two connector processes are
// accidentally pointed at one state directory — a case an in-memory set gets silently wrong.
type Ledger struct {
	directory string
}

func NewLedger(directory string) (*Ledger, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("sealedconfig: create ledger %s: %w", directory, err)
	}
	return &Ledger{directory: directory}, nil
}

// Outcome reports what happened to an envelope, and whether it has been seen at all.
//
// A caller that finds an envelope already recorded must report that outcome rather than applying
// again. Returning the previous answer instead of a bare "duplicate" is what lets the control
// plane close the loop after a lost acknowledgement without ever seeing a different story.
func (l *Ledger) Outcome(envelopeID string) (string, bool, error) {
	raw, err := os.ReadFile(l.path(envelopeID)) //nolint:gosec // digest-named path inside the ledger
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("sealedconfig: read ledger entry: %w", err)
	}
	return strings.TrimSpace(string(raw)), true, nil
}

// Record writes the outcome of an envelope, once.
//
// Recorded *after* the configuration is written, not before. This is the opposite trade from the
// job replay ledger, and deliberately so: re-writing an identical configuration is harmless, while
// a destructive job that ran twice is not. Here the failure mode worth avoiding is "the operator
// configured a source and nothing happened", so a crash between applying and recording costs one
// redundant re-apply instead of losing the configuration entirely.
//
// An entry that already exists is left alone: the first answer is the one the control plane may
// already have seen, and rewriting it would let a redelivery change history.
func (l *Ledger) Record(envelopeID, outcome string) error {
	file, err := os.OpenFile(l.path(envelopeID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("sealedconfig: record outcome: %w", err)
	}
	if _, err := file.WriteString(outcome); err != nil {
		_ = file.Close()
		return fmt.Errorf("sealedconfig: record outcome: %w", err)
	}
	return file.Close()
}

// path names the entry by digest rather than by the envelope id.
//
// An envelope id arrives over the network. Naming a file after it directly would let its
// characters decide where the file lands; hashing removes both that and the filesystem's opinion
// about case, which on macOS would otherwise merge two distinct ids into one entry.
func (l *Ledger) path(envelopeID string) string {
	sum := sha256.Sum256([]byte(envelopeID))
	return filepath.Join(l.directory, hex.EncodeToString(sum[:]))
}

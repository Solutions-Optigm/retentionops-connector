package sealedconfig

import (
	"errors"
	"fmt"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
)

// ErrUnknownSource is returned for an envelope naming a source this connector does not serve.
//
// The console is the authority on which sources exist; a connector creating one because an
// envelope mentioned it would let the control plane add targets to a host by asserting them.
var ErrUnknownSource = errors.New("sealedconfig: envelope names a source this connector does not serve")

// Apply writes an opened configuration into the connector's own configuration.
//
// Only the connection is touched: where the database is, which database it is, which TLS mode to
// verify under, and which two roles to assume. Everything else on the source is left exactly as
// it was — most importantly `Safety`, which is the local policy the control plane may neither
// read nor widen (I32, rule 8), and `Mode`, which is who decides whether this source may execute
// at all.
//
// The secret references are untouched for the same reason plus one more: they are file paths on
// this host, and no envelope carries a password to put behind them (ADR-034). An operator who
// changes the reader role still enters that role's password locally.
func Apply(configuration *config.Config, sourceID string, opened SourceConfiguration) error {
	source, known := configuration.Sources[sourceID]
	if !known || source == nil {
		return ErrUnknownSource
	}

	source.Host = opened.Host
	source.Port = opened.Port
	source.Database = opened.Database
	source.TLS.Mode = opened.TLSMode
	source.Reader.Username = opened.ReaderRole
	if opened.ExecutorRole != "" {
		source.Executor.Username = opened.ExecutorRole
	}

	// Validated after the edit rather than trusted before it. The envelope came from a browser
	// and was authenticated, not vetted: authenticity says who wrote it, never that what they
	// wrote is a configuration this connector can run.
	if err := configuration.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	return nil
}

// ErrInvalidConfiguration is returned when an authenticated envelope would produce a
// configuration the connector refuses to run.
var ErrInvalidConfiguration = errors.New("sealedconfig: envelope does not produce a valid configuration")

// OutcomeFor maps a refusal to the code the control plane records.
//
// Codes, never messages. The underlying error can name a host — it is written to the local log,
// where the customer already has that information — and the control plane gets the class alone.
func OutcomeFor(err error) string {
	switch {
	case err == nil:
		return OutcomeApplied
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNotYetValid):
		return OutcomeRefusedExpired
	case errors.Is(err, ErrWrongRecipient), errors.Is(err, ErrTooLarge), errors.Is(err, ErrVersion):
		return OutcomeRefusedUnreadable
	default:
		return OutcomeRefusedInvalid
	}
}

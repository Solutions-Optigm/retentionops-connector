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

// Prepare returns the source as it would be after applying, having validated the whole
// configuration that would result. Nothing the connector is running is touched.
//
// Separating "what it would become" from "make it so" is what lets a caller persist first and
// activate second. An implementation that mutated here and validated afterwards would leave a
// connector running a configuration it had just refused to write down — REFUSED would then mean
// "not saved, but in force", which is the one outcome an operator cannot act on.
//
// Only the connection is prepared: where the database is, which database it is, which TLS mode to
// verify under, and which two roles to assume. Everything else on the source is carried over
// untouched — most importantly `Safety`, which is the local policy the control plane may neither
// read nor widen (I32, rule 8), and `Mode`, which decides whether this source may execute at all.
// The secret references are carried over for the same reason plus one more: they are paths on
// this host, and no envelope carries a password to put behind them (ADR-034).
func Prepare(configuration *config.Config, sourceID string, opened SourceConfiguration) (*config.Source, error) {
	current, known := configuration.Sources[sourceID]
	if !known || current == nil {
		return nil, ErrUnknownSource
	}

	candidate := *current
	candidate.Host = opened.Host
	candidate.Port = opened.Port
	candidate.Database = opened.Database
	candidate.TLS.Mode = opened.TLSMode
	candidate.Reader.Username = opened.ReaderRole
	if opened.ExecutorRole != "" {
		candidate.Executor.Username = opened.ExecutorRole
	}

	// A clone rather than an edit: validation must judge the whole configuration, and the running
	// one must survive being judged.
	proposed := *configuration
	proposed.Sources = make(map[string]*config.Source, len(configuration.Sources))
	for id, source := range configuration.Sources {
		proposed.Sources[id] = source
	}
	proposed.Sources[sourceID] = &candidate

	// Validated after the substitution rather than trusted before it: the envelope came from a
	// browser and was authenticated, not vetted. Authenticity says who wrote it, never that what
	// they wrote is a configuration this connector can run.
	if err := proposed.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}
	return &candidate, nil
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

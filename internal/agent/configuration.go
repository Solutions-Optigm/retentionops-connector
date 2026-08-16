package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
	"github.com/solutions-optigm/retentionops-connector/internal/sealedconfig"
)

// applyPendingConfigurations collects, opens and applies whatever the console has sealed.
//
// Called from the poll loop while idle, never from a goroutine: that loop is the only reader of
// the source map, and reconfiguring a source from somewhere else would be a data race inside a
// process holding delete rights on a production database. Waiting for idle also means a source is
// never reconfigured halfway through a job running against it.
//
// Every failure here is local and non-fatal. A connector that cannot be configured must keep
// polling, executing and reporting exactly as before — a configuration that did not arrive is not
// a reason to stop honouring the one already in force.
func (a *Agent) applyPendingConfigurations(ctx context.Context) {
	documents, err := a.client.PendingConfigurations(ctx)
	if err != nil {
		a.log.Warn("collecting sealed configurations failed", "error", err)
		return
	}
	for _, document := range documents {
		a.applyOneConfiguration(ctx, document)
	}
}

func (a *Agent) applyOneConfiguration(ctx context.Context, document json.RawMessage) {
	var envelope sealedconfig.Envelope
	if err := json.Unmarshal(document, &envelope); err != nil {
		// No envelope id means nothing to acknowledge against, and nothing to remember. The
		// control plane will redeliver; a document this malformed is a bug on our side of the
		// wire, and the local log is where it can be seen with its detail intact.
		a.log.Warn("a relayed document is not a v1 sealed configuration", "error", err)
		return
	}

	// Asked before opening. A redelivery after a lost acknowledgement must produce the answer the
	// first attempt produced, not a second application of the same configuration.
	if previous, seen, err := a.configLedger.Outcome(envelope.EnvelopeID); err != nil {
		a.log.Warn("reading the configuration ledger failed",
			"envelope_id", envelope.EnvelopeID, "error", err)
		return
	} else if seen {
		// An envelope that was applied reports ALREADY_APPLIED, which tells the control plane
		// this was a redelivery rather than a second application. A refusal replays its own code
		// instead: answering ALREADY_APPLIED for something that never applied would be a lie the
		// console would render as success.
		answer := previous
		if previous == sealedconfig.OutcomeApplied {
			answer = sealedconfig.OutcomeAlreadyApplied
		}
		a.acknowledgeConfiguration(ctx, envelope.EnvelopeID, answer)
		return
	}

	outcome := a.openAndApply(envelope)
	// Recorded before the acknowledgement is sent, so a crash in between cannot lose the fact
	// that the configuration was already written to disk.
	if err := a.configLedger.Record(envelope.EnvelopeID, outcome); err != nil {
		a.log.Error("recording a configuration outcome failed",
			"envelope_id", envelope.EnvelopeID, "error", err)
		return
	}
	a.acknowledgeConfiguration(ctx, envelope.EnvelopeID, outcome)
}

// openAndApply returns the outcome code, having logged the detail locally.
//
// The sequence is validate, persist, then activate — never the other way round. A configuration
// becomes the one this connector is running only after it is durably on disk, so REFUSED means
// exactly one thing: nothing changed, on disk or in memory. An operator reading that outcome can
// retry, and a connector that failed to be configured is still running the configuration its
// owner last approved.
//
// The error itself never travels: it can name a host, and the customer already has that detail on
// this machine. The control plane receives the class alone.
func (a *Agent) openAndApply(envelope sealedconfig.Envelope) string {
	key, err := a.identity.EncryptionKey()
	if err != nil {
		a.log.Error("the sealing key is unavailable", "error", err)
		return sealedconfig.OutcomeRefusedUnreadable
	}
	opened, err := sealedconfig.Open(
		envelope, key, a.identity.ConnectorID, a.identity.OrganizationID, time.Now().UTC(),
	)
	if err != nil {
		a.log.Warn("a sealed configuration could not be opened",
			"envelope_id", envelope.EnvelopeID, "error", err)
		return sealedconfig.OutcomeFor(err)
	}

	candidate, proposed, err := sealedconfig.Prepare(a.config, envelope.SourceID, opened)
	if err != nil {
		a.log.Warn("a sealed configuration was refused",
			"envelope_id", envelope.EnvelopeID, "error", err)
		return sealedconfig.OutcomeFor(err)
	}
	if err := config.Persist(a.configPath, proposed); err != nil {
		// Nothing has been activated, so there is nothing to roll back: the running configuration
		// was never touched. Reporting refused is therefore literally true rather than a hedge.
		a.log.Error("persisting a sealed configuration failed",
			"envelope_id", envelope.EnvelopeID, "error", err)
		return sealedconfig.OutcomeRefusedInvalid
	}

	// Activated only now, and in place, because the poll loop holds a pointer to this map.
	a.config.Sources[envelope.SourceID] = candidate
	a.log.Info("source configuration applied",
		"envelope_id", envelope.EnvelopeID, "data_source_id", envelope.SourceID)
	return sealedconfig.OutcomeApplied
}

func (a *Agent) acknowledgeConfiguration(ctx context.Context, envelopeID, outcome string) {
	if err := a.client.AcknowledgeConfiguration(ctx, envelopeID, outcome); err != nil {
		// Not fatal, and not retried here: the envelope stays pending, comes back on the next
		// pass, and the ledger answers with this same outcome. That is what makes an at-least-once
		// transport safe to acknowledge unreliably.
		a.log.Warn("acknowledging a sealed configuration failed",
			"envelope_id", envelopeID, "error", err)
	}
}

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/solutions-optigm/retentionops-connector/internal/identity"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

func TestPauseIsHeldUntilAFreshRunDecision(t *testing.T) {
	t.Parallel()

	actions := []protocolv1.ControlAction{protocolv1.ControlPause, protocolv1.ControlRun}
	call := 0
	events := make([]string, 0, 2)
	agent := checkpointTestAgent()
	agent.control = func(context.Context, string) (*protocolv1.ExecutionControl, error) {
		action := actions[call]
		call++
		return &protocolv1.ExecutionControl{Action: action, ExecutionVersion: int64(call)}, nil
	}
	agent.event = func(_ context.Context, event protocolv1.JobEvent) error {
		events = append(events, event.EventType)
		return nil
	}

	sequence := 0
	version := int64(0)
	err := agent.awaitControl(context.Background(), checkpointTestJob(), &sequence, &version, 1_000)
	if err != nil {
		t.Fatalf("checkpoint did not resume: %v", err)
	}
	if call != 2 {
		t.Fatalf("the connector did not remain paused until RUN: calls=%d", call)
	}
	if len(events) != 2 || events[0] != protocolv1.EventPaused || events[1] != protocolv1.EventResumed {
		t.Fatalf("pause lifecycle was not reported: %v", events)
	}
}

func TestMissingControlFailsClosedUntilCancellation(t *testing.T) {
	t.Parallel()

	call := 0
	agent := checkpointTestAgent()
	agent.control = func(context.Context, string) (*protocolv1.ExecutionControl, error) {
		call++
		if call == 1 {
			return nil, errors.New("control plane unavailable")
		}
		return &protocolv1.ExecutionControl{
			Action: protocolv1.ControlCancel, ExecutionVersion: 2,
		}, nil
	}

	sequence := 0
	version := int64(0)
	err := agent.awaitControl(context.Background(), checkpointTestJob(), &sequence, &version, 0)
	var cancelled *controlCancelledError
	if !errors.As(err, &cancelled) {
		t.Fatalf("expected a checkpoint cancellation after the outage, got %v", err)
	}
	if call != 2 {
		t.Fatalf("control loss must retry locally rather than authorize a batch: calls=%d", call)
	}
}

func checkpointTestAgent() *Agent {
	return &Agent{
		identity: &identity.Identity{
			ConnectorID:    "22222222-2222-4222-8222-222222222222",
			OrganizationID: "11111111-1111-4111-8111-111111111111",
		},
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		event:        func(context.Context, protocolv1.JobEvent) error { return nil },
		controlRetry: time.Nanosecond,
	}
}

func checkpointTestJob() *protocolv1.JobEnvelope {
	return &protocolv1.JobEnvelope{JobID: "33333333-3333-4333-8333-333333333333"}
}

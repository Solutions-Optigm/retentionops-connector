package policy

import (
	"encoding/json"
	"testing"
	"time"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

var now = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func safety() *Safety {
	return &Safety{
		AllowedSchemas:  []string{"application"},
		RequireApproval: true,
		Drift: DriftPolicy{
			Mode:                "bounded",
			ExactMatchBelowRows: 1000,
			MaxRows:             100,
			MaxBasisPoints:      50,
		},
		MaxDeleteRows:           50000,
		MaxBatchSize:            1000,
		StatementTimeoutSeconds: 30,
		LockTimeoutSeconds:      5,
		Tables: []TableRule{
			{
				Schema:           "application",
				Table:            "audit_logs",
				Actions:          []Action{ActionInspect, ActionDelete},
				RetentionColumns: []string{"created_at", "legal_hold"},
				MaxDeleteRows:    50000,
				MaxBatchSize:     1000,
			},
			{
				Schema:           "application",
				Table:            "users",
				Actions:          []Action{ActionInspect},
				RetentionColumns: []string{"created_at"},
			},
		},
	}
}

func job(operation protocolv1.Operation, mutate ...func(*protocolv1.JobEnvelope)) *protocolv1.JobEnvelope {
	envelope := &protocolv1.JobEnvelope{
		ProtocolVersion: protocolv1.Version,
		Operation:       operation,
		Target:          &protocolv1.Target{Schema: "application", Table: "audit_logs"},
		Predicate: &protocolv1.Predicate{
			Type:   protocolv1.PredicateBefore,
			Column: "created_at",
			Value:  now.AddDate(-7, 0, 0),
		},
		Holds: []protocolv1.Condition{{
			Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true"),
		}},
		Limits: &protocolv1.Limits{
			BatchSize:               1000,
			MaxRows:                 50000,
			StatementTimeoutSeconds: 30,
		},
		Approval: &protocolv1.Approval{
			ID:         "9f3b1c2d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
			ApprovedAt: now.Add(-time.Hour),
			ExpiresAt:  now.Add(time.Hour),
		},
		PlanDigest: "sha256:" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		Drift:      &protocolv1.Drift{ExpectedRows: 10000, MaxRows: 50, MaxBasisPoints: 50},
	}
	for _, apply := range mutate {
		apply(envelope)
	}
	return envelope
}

func TestAnAllowedDeleteIsAuthorized(t *testing.T) {
	decision := safety().Authorize(job(protocolv1.OpDelete), now)
	if !decision.Allowed {
		t.Fatalf("expected the allow-listed delete to pass, got %s: %s", decision.Code, decision.Reason)
	}
}

// Each case below is a way the control plane could be wrong — by bug, by compromise, or by
// asking for something the customer never granted — and the code the connector must answer.
func TestTheLocalPolicyRefuses(t *testing.T) {
	cases := []struct {
		name string
		job  *protocolv1.JobEnvelope
		code protocolv1.DenialCode
	}{
		{
			name: "a delete on a table that only grants inspect",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Target = &protocolv1.Target{Schema: "application", Table: "users"}
			}),
			code: protocolv1.DeniedTargetNotAllowed,
		},
		{
			name: "a table absent from the allow-list",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Target = &protocolv1.Target{Schema: "application", Table: "payments"}
			}),
			code: protocolv1.DeniedTargetNotAllowed,
		},
		{
			name: "a schema absent from allowed_schemas",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Target = &protocolv1.Target{Schema: "public", Table: "audit_logs"}
			}),
			code: protocolv1.DeniedTargetNotAllowed,
		},
		{
			name: "a predicate on a column that is not a retention column",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Predicate.Column = "email"
			}),
			code: protocolv1.DeniedColumnNotAllowed,
		},
		{
			name: "more rows than the local ceiling",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Limits.MaxRows = 50001
			}),
			code: protocolv1.DeniedRowLimit,
		},
		{
			name: "a batch larger than the local ceiling",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Limits.BatchSize = 5000
			}),
			code: protocolv1.DeniedBatchLimit,
		},
		{
			name: "a destructive job with no approval",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Approval = nil
			}),
			code: protocolv1.DeniedApprovalRequired,
		},
		{
			name: "a destructive job whose approval has expired",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Approval.ExpiresAt = now.Add(-time.Minute)
			}),
			code: protocolv1.DeniedApprovalExpired,
		},
		{
			name: "a destructive job with looser drift than the local maximum",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Drift.MaxRows = 101
			}),
			code: protocolv1.DeniedByLocalPolicy,
		},
		{
			name: "a small destructive job with any drift",
			job: job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
				j.Drift.ExpectedRows = 999
				j.Drift.MaxRows = 1
			}),
			code: protocolv1.DeniedByLocalPolicy,
		},
		{
			name: "an operation this connector does not implement",
			job: job("POSTGRES_TRUNCATE", func(j *protocolv1.JobEnvelope) {
				j.Approval = nil
			}),
			code: protocolv1.DeniedUnknownOperation,
		},
	}

	rules := safety()
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision := rules.Authorize(testCase.job, now)
			if decision.Allowed {
				t.Fatalf("expected a refusal, the job was authorized")
			}
			if decision.Code != testCase.code {
				t.Fatalf("expected %s, got %s (%s)", testCase.code, decision.Code, decision.Reason)
			}
		})
	}
}

func TestStrictDriftModeCannotBeWidenedRemotely(t *testing.T) {
	rules := safety()
	rules.Drift = DriftPolicy{Mode: "strict"}
	decision := rules.Authorize(job(protocolv1.OpDelete), now)
	if decision.Allowed || decision.Code != protocolv1.DeniedByLocalPolicy {
		t.Fatalf("strict local drift must refuse a tolerant job, got %+v", decision)
	}

	decision = rules.Authorize(job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
		j.Drift.MaxRows = 0
		j.Drift.MaxBasisPoints = 0
	}), now)
	if !decision.Allowed {
		t.Fatalf("strict local drift must accept an exact job, got %s: %s", decision.Code, decision.Reason)
	}
}

// The control plane can lower a timeout but never raise one past the local maximum, and it
// cannot reach past the local ceiling by asking for a bigger scope — that path is a refusal,
// tested above, not a clamp.
func TestProtectiveTimeoutsAreLoweredToTheLocalMaximum(t *testing.T) {
	rules := safety()
	rules.StatementTimeoutSeconds = 10
	decision := rules.Authorize(job(protocolv1.OpCount, func(j *protocolv1.JobEnvelope) {
		j.Limits.StatementTimeoutSeconds = 3600
	}), now)
	if !decision.Allowed {
		t.Fatalf("expected the count to be authorized, got %s", decision.Code)
	}
	if decision.Effective.StatementTimeoutSeconds != 10 {
		t.Fatalf("expected the statement timeout lowered to 10, got %d", decision.Effective.StatementTimeoutSeconds)
	}
}

func TestApprovalCanBeWaivedOnlyByTheLocalFile(t *testing.T) {
	rules := safety()
	rules.RequireApproval = false
	decision := rules.Authorize(job(protocolv1.OpDelete, func(j *protocolv1.JobEnvelope) {
		j.Approval = nil
	}), now)
	if !decision.Allowed {
		t.Fatalf("with require_approval disabled locally the delete should pass, got %s", decision.Code)
	}
}

func TestValidateRefusesAPolicyThatCannotMeanWhatItSays(t *testing.T) {
	cases := []struct {
		name  string
		build func() *Safety
	}{
		{
			name:  "no reachable schema",
			build: func() *Safety { s := safety(); s.AllowedSchemas = nil; return s },
		},
		{
			name: "a table outside the allowed schemas",
			build: func() *Safety {
				s := safety()
				s.Tables[0].Schema = "other"
				return s
			},
		},
		{
			name: "delete granted without a retention column",
			build: func() *Safety {
				s := safety()
				s.Tables[0].RetentionColumns = nil
				return s
			},
		},
		{
			name: "delete granted with no row ceiling anywhere",
			build: func() *Safety {
				s := safety()
				s.MaxDeleteRows = 0
				s.Tables[0].MaxDeleteRows = 0
				return s
			},
		},
		{
			name: "the same table declared twice",
			build: func() *Safety {
				s := safety()
				s.Tables = append(s.Tables, s.Tables[0])
				return s
			},
		},
		{
			name: "an identifier that is not a plain identifier",
			build: func() *Safety {
				s := safety()
				s.Tables[0].Table = `audit_logs"; DROP TABLE users; --`
				return s
			},
		},
		{
			name: "an unknown action",
			build: func() *Safety {
				s := safety()
				s.Tables[0].Actions = []Action{"truncate"}
				return s
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.build().Validate(); err == nil {
				t.Fatal("expected the policy to be refused at startup")
			}
		})
	}
}

func TestInspectionOperationsNeedNoTarget(t *testing.T) {
	rules := safety()
	for _, operation := range []protocolv1.Operation{protocolv1.OpTestConnection, protocolv1.OpDiscover} {
		decision := rules.Authorize(&protocolv1.JobEnvelope{Operation: operation}, now)
		if !decision.Allowed {
			t.Fatalf("%s should not require a target, got %s", operation, decision.Code)
		}
	}
}

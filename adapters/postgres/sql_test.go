package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

var target = protocolv1.Target{Schema: "application", Table: "audit_logs"}

func TestEveryStatementBindsItsValueRatherThanRenderingIt(t *testing.T) {
	predicate := protocolv1.Predicate{Type: protocolv1.PredicateBefore, Column: "created_at"}
	count, _, err := countStatement(target, predicate, nil, []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}})
	if err != nil {
		t.Fatalf("count statement: %v", err)
	}
	deletion, _, err := deleteBatchStatement(target, predicate, nil, []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}})
	if err != nil {
		t.Fatalf("delete statement: %v", err)
	}
	statements := []string{
		count,
		deletion,
		discoverStatement,
		sizeStatement,
		versionStatement,
	}
	for _, statement := range statements {
		if strings.Contains(statement, "'2") || strings.Contains(statement, "%s") {
			t.Fatalf("a literal value reached a statement: %s", statement)
		}
	}
	if !strings.Contains(count, "$1") {
		t.Fatal("the retention boundary must be a bound parameter")
	}
	if !strings.Contains(deletion, "$3") {
		t.Fatal("the batch size must be a bound parameter")
	}
}

func TestIdentifiersAreQuotedAndSchemaQualified(t *testing.T) {
	predicate := protocolv1.Predicate{Type: protocolv1.PredicateBefore, Column: "created_at"}
	statement, _, err := deleteBatchStatement(target, predicate, nil, []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}})
	if err != nil {
		t.Fatalf("delete statement: %v", err)
	}
	if !strings.Contains(statement, `"application"."audit_logs"`) {
		t.Fatalf("expected a quoted, qualified table name in: %s", statement)
	}
	if !strings.Contains(statement, `"created_at"`) {
		t.Fatalf("expected a quoted column name in: %s", statement)
	}
}

func TestConditionsAndHoldsRemainParameterized(t *testing.T) {
	predicate := protocolv1.Predicate{Type: protocolv1.PredicateBefore, Column: "created_at"}
	condition := &protocolv1.Condition{All: []protocolv1.Condition{
		{Column: "tenant_id", Operator: "in", Value: json.RawMessage(`[10, 20]`)},
		{Not: &protocolv1.Condition{Column: "status", Operator: "eq", Value: json.RawMessage(`"open"`)}},
	}}
	holds := []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}}
	statement, arguments, err := countStatement(target, predicate, condition, holds)
	if err != nil {
		t.Fatalf("count statement: %v", err)
	}
	for _, forbidden := range []string{"10", "20", "open", "true"} {
		if strings.Contains(statement, forbidden) {
			t.Fatalf("literal %q reached SQL: %s", forbidden, statement)
		}
	}
	if !strings.Contains(statement, `NOT (`) || len(arguments) != 5 {
		t.Fatalf("conditions or holds were lost: %s args=%v", statement, arguments)
	}
}

func TestDeleteRechecksEligibilityWithoutRequiringUpdatePrivilege(t *testing.T) {
	predicate := protocolv1.Predicate{Type: protocolv1.PredicateBefore, Column: "created_at"}
	holds := []protocolv1.Condition{{Column: "legal_hold", Operator: "eq", Value: json.RawMessage("true")}}
	statement, _, err := deleteBatchStatement(target, predicate, nil, holds)
	if err != nil {
		t.Fatalf("delete statement: %v", err)
	}
	if strings.Contains(statement, "FOR UPDATE") || strings.Contains(statement, "SKIP LOCKED") {
		t.Fatalf("executor would require UPDATE privilege: %s", statement)
	}
	if strings.Count(statement, `NOT (("legal_hold" = $2))`) != 2 {
		t.Fatalf("hold exclusion must be rechecked by the outer DELETE: %s", statement)
	}
}

// The identifier gate is the last line before a name becomes SQL. Reaching it with something
// that was never validated is a bug in the caller, and it must stop the process rather than
// produce a statement — an escaped-quote injection attempt is exactly the input this refuses.
func TestAnUnvalidatedIdentifierPanicsRatherThanBecomingSQL(t *testing.T) {
	for _, name := range []string{
		`audit_logs"; DROP TABLE users; --`,
		`Audit_Logs`,
		``,
		`public.audit_logs`,
		`audit logs`,
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("quoteIdentifier(%q) produced SQL instead of refusing", name)
				}
			}()
			_ = quoteIdentifier(name)
		})
	}
}

func TestOnlyTheTwoRetentionComparisonsExist(t *testing.T) {
	if comparison(protocolv1.PredicateBefore) != "<" {
		t.Fatal("BEFORE must render as <")
	}
	if comparison(protocolv1.PredicateOnOrBefore) != "<=" {
		t.Fatal("ON_OR_BEFORE must render as <=")
	}
	// Anything the protocol validator would have rejected still renders as the strictest
	// comparison rather than an unbounded one.
	if comparison("ANYTHING_ELSE") != "<" {
		t.Fatal("an unknown predicate type must not widen the comparison")
	}
}

func TestTheConnectionStringNeverCarriesAPassword(t *testing.T) {
	built := dsn("db.internal", 5432, "production", "retentionops_reader", "verify-full", "/etc/ca.pem", 10)
	if strings.Contains(built, "password") {
		t.Fatalf("the DSN must not have a password field: %s", built)
	}
	for _, expected := range []string{"sslmode='verify-full'", "sslrootcert='/etc/ca.pem'", "connect_timeout=10"} {
		if !strings.Contains(built, expected) {
			t.Fatalf("expected %s in %s", expected, built)
		}
	}
}

func TestTimeoutsAreAlwaysSetAndAlwaysIntegers(t *testing.T) {
	statements := timeoutStatements(protocolv1.Limits{StatementTimeoutSeconds: 30, LockTimeoutSeconds: 5})
	joined := strings.Join(statements, "; ")
	for _, expected := range []string{
		"SET LOCAL statement_timeout = 30000",
		"SET LOCAL idle_in_transaction_session_timeout = 30000",
		"SET LOCAL lock_timeout = 5000",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in %q", expected, joined)
		}
	}
}

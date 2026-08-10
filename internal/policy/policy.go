// Package policy is the connector's second trust boundary, and the most important one.
//
// The first boundary is cryptographic: a job must carry a valid signature from the control plane
// this connector enrolled with. That boundary answers "did RetentionOps really ask for this". It
// does not answer "should RetentionOps be able to ask for this at all", and those are different
// questions the moment you assume the control plane can be compromised.
//
// This package answers the second one, from a file that lives on the customer's host and that no
// part of the RetentionOps protocol can read or write. There is deliberately no operation, no
// message and no configuration path by which the control plane can widen its own permissions
// here — that absence is the control.
package policy

import (
	"fmt"
	"time"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// Action is what a customer grants over a table. Two verbs, because a third would be a third
// thing to reason about in an audit.
type Action string

const (
	// ActionInspect permits counting and measuring. It never returns rows.
	ActionInspect Action = "inspect"
	// ActionDelete permits removing rows that match an approved retention predicate.
	ActionDelete Action = "delete"
)

// TableRule is one allow-list entry: a named table, the verbs allowed on it, the columns a
// retention predicate may reference, and the ceilings that apply.
type TableRule struct {
	Schema           string   `yaml:"schema" json:"schema"`
	Table            string   `yaml:"table" json:"table"`
	Actions          []Action `yaml:"actions" json:"actions"`
	RetentionColumns []string `yaml:"retention_columns" json:"retention_columns"`
	MaxDeleteRows    int      `yaml:"max_delete_rows" json:"max_delete_rows"`
	MaxBatchSize     int      `yaml:"max_batch_size" json:"max_batch_size"`
}

// DriftPolicy is the widest recount difference this customer permits. The control plane may
// request less tolerance in a signed job, never more.
type DriftPolicy struct {
	Mode                string `yaml:"mode" json:"mode"`
	ExactMatchBelowRows int64  `yaml:"exact_match_below_rows" json:"exact_match_below_rows"`
	MaxRows             int64  `yaml:"max_rows" json:"max_rows"`
	MaxBasisPoints      int    `yaml:"max_basis_points" json:"max_basis_points"`
}

// Safety is the local policy for one data source.
type Safety struct {
	AllowedSchemas []string `yaml:"allowed_schemas" json:"allowed_schemas"`
	//: A destructive job without a human approval is refused here, independently of whether the
	//: control plane thinks it has one. Turning this off is a customer decision that has to be
	//: made in a file on their own host.
	RequireApproval bool        `yaml:"require_approval" json:"require_approval"`
	Drift           DriftPolicy `yaml:"drift" json:"drift"`

	MaxDeleteRows           int `yaml:"max_delete_rows" json:"max_delete_rows"`
	MaxBatchSize            int `yaml:"max_batch_size" json:"max_batch_size"`
	StatementTimeoutSeconds int `yaml:"statement_timeout_seconds" json:"statement_timeout_seconds"`
	LockTimeoutSeconds      int `yaml:"lock_timeout_seconds" json:"lock_timeout_seconds"`
	MaxDurationSeconds      int `yaml:"max_duration_seconds" json:"max_duration_seconds"`

	Tables []TableRule `yaml:"tables" json:"tables"`
}

// Decision is the outcome of an authorization. Reason is written to the local log and never
// leaves the host: the customer already has the detail, and the control plane gets the stable
// code so it can be acted on without being parsed.
type Decision struct {
	Allowed bool
	Code    protocolv1.DenialCode
	Reason  string
	// Effective carries the ceilings actually applied, after protective timeouts have been
	// lowered to the local maximum.
	Effective protocolv1.Limits
}

func allow(effective protocolv1.Limits) Decision {
	return Decision{Allowed: true, Effective: effective}
}

func deny(code protocolv1.DenialCode, format string, args ...any) Decision {
	return Decision{Allowed: false, Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Validate rejects a policy that cannot mean what its author intended.
//
// A misconfigured allow-list is more dangerous than an absent one, because it looks like a
// control. Every failure here is a startup failure: the connector refuses to run rather than run
// with a policy it had to interpret.
func (s *Safety) Validate() error {
	if len(s.AllowedSchemas) == 0 {
		return fmt.Errorf("allowed_schemas is empty: a source with no reachable schema is a misconfiguration, not a lockdown")
	}
	for _, schema := range s.AllowedSchemas {
		if !protocolv1.IsIdentifier(schema) {
			return fmt.Errorf("allowed schema %q is not a plain lowercase identifier", schema)
		}
	}
	seen := make(map[string]struct{}, len(s.Tables))
	for index := range s.Tables {
		rule := &s.Tables[index]
		if err := s.validateTable(rule); err != nil {
			return err
		}
		key := rule.Schema + "." + rule.Table
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("table %s is declared twice; which entry applies would be ambiguous", key)
		}
		seen[key] = struct{}{}
	}
	if s.MaxDeleteRows < 0 || s.MaxBatchSize < 0 {
		return fmt.Errorf("source ceilings cannot be negative")
	}
	if err := s.Drift.validate(); err != nil {
		return err
	}
	return nil
}

func (d *DriftPolicy) validate() error {
	if d.Mode != "strict" && d.Mode != "bounded" {
		return fmt.Errorf("drift.mode must be strict or bounded")
	}
	if d.ExactMatchBelowRows < 0 || d.MaxRows < 0 || d.MaxBasisPoints < 0 || d.MaxBasisPoints > 10_000 {
		return fmt.Errorf("drift limits are out of range")
	}
	if d.Mode == "strict" && (d.ExactMatchBelowRows != 0 || d.MaxRows != 0 || d.MaxBasisPoints != 0) {
		return fmt.Errorf("strict drift mode cannot carry bounded tolerances")
	}
	if d.Mode == "bounded" && (d.ExactMatchBelowRows == 0 || d.MaxRows == 0 || d.MaxBasisPoints == 0) {
		return fmt.Errorf("bounded drift mode needs exact_match_below_rows, max_rows and max_basis_points")
	}
	return nil
}

func (s *Safety) validateTable(rule *TableRule) error {
	if !protocolv1.IsIdentifier(rule.Schema) || !protocolv1.IsIdentifier(rule.Table) {
		return fmt.Errorf("table %q.%q is not a pair of plain lowercase identifiers", rule.Schema, rule.Table)
	}
	if !s.schemaAllowed(rule.Schema) {
		return fmt.Errorf("table %s.%s names a schema absent from allowed_schemas", rule.Schema, rule.Table)
	}
	if len(rule.Actions) == 0 {
		return fmt.Errorf("table %s.%s grants no action; remove the entry instead", rule.Schema, rule.Table)
	}
	for _, action := range rule.Actions {
		if action != ActionInspect && action != ActionDelete {
			return fmt.Errorf("table %s.%s grants unknown action %q", rule.Schema, rule.Table, action)
		}
	}
	for _, column := range rule.RetentionColumns {
		if !protocolv1.IsIdentifier(column) {
			return fmt.Errorf("table %s.%s lists retention column %q, which is not a plain lowercase identifier", rule.Schema, rule.Table, column)
		}
	}
	if rule.allows(ActionDelete) {
		if len(rule.RetentionColumns) == 0 {
			return fmt.Errorf("table %s.%s allows delete without naming a retention column; a delete with no bounded predicate is a table drop in slow motion", rule.Schema, rule.Table)
		}
		if rule.MaxDeleteRows <= 0 && s.MaxDeleteRows <= 0 {
			return fmt.Errorf("table %s.%s allows delete without any row ceiling, at table or source level", rule.Schema, rule.Table)
		}
	}
	return nil
}

func (s *Safety) schemaAllowed(schema string) bool {
	for _, candidate := range s.AllowedSchemas {
		if candidate == schema {
			return true
		}
	}
	return false
}

func (r *TableRule) allows(action Action) bool {
	for _, candidate := range r.Actions {
		if candidate == action {
			return true
		}
	}
	return false
}

func (r *TableRule) allowsColumn(column string) bool {
	for _, candidate := range r.RetentionColumns {
		if candidate == column {
			return true
		}
	}
	return false
}

// GrantsDelete reports whether any table in this policy grants the destructive verb.
//
// The connector uses it to decide whether an executor identity has to be configured at all. A
// source configured for inspection only never needs a destructive database role to exist, which
// is the cheapest possible way to be safe.
func (s *Safety) GrantsDelete() bool {
	for index := range s.Tables {
		if s.Tables[index].allows(ActionDelete) {
			return true
		}
	}
	return false
}

// AllowedTableCount is what the heartbeat reports: how wide the door was opened, not which
// tables are behind it.
func (s *Safety) AllowedTableCount() int { return len(s.Tables) }

// Rule finds the allow-list entry for a target, or nil.
func (s *Safety) Rule(target protocolv1.Target) *TableRule {
	for index := range s.Tables {
		rule := &s.Tables[index]
		if rule.Schema == target.Schema && rule.Table == target.Table {
			return rule
		}
	}
	return nil
}

// Authorize decides whether a structurally valid, correctly signed job may run.
//
// It assumes the signature has already been checked and the job addressed to this connector —
// see internal/jobs. Deciding those separately is what allows this function to be a pure
// function of (policy, job, clock) and therefore to be tested exhaustively.
func (s *Safety) Authorize(job *protocolv1.JobEnvelope, now time.Time) Decision {
	switch job.Operation {
	case protocolv1.OpTestConnection, protocolv1.OpDiscover:
		// Neither reads a row. Discovery is still confined to allowed_schemas by the adapter,
		// so a source the customer scoped to one schema never reveals the rest of the database.
		return allow(protocolv1.Limits{})
	case protocolv1.OpCount, protocolv1.OpDelete:
	default:
		return deny(protocolv1.DeniedUnknownOperation, "operation %q is not implemented", job.Operation)
	}

	if job.Target == nil || job.Predicate == nil || job.Limits == nil {
		return deny(protocolv1.DeniedByLocalPolicy, "operation %q arrived without its operands", job.Operation)
	}
	if !s.schemaAllowed(job.Target.Schema) {
		return deny(protocolv1.DeniedTargetNotAllowed, "schema %q is not in allowed_schemas", job.Target.Schema)
	}
	rule := s.Rule(*job.Target)
	if rule == nil {
		return deny(protocolv1.DeniedTargetNotAllowed, "table %s is not in the local allow-list", job.Target)
	}

	required := ActionInspect
	if job.Operation == protocolv1.OpDelete {
		required = ActionDelete
	}
	if !rule.allows(required) {
		return deny(protocolv1.DeniedTargetNotAllowed, "table %s does not grant %q", job.Target, required)
	}
	if !rule.allowsColumn(job.Predicate.Column) {
		return deny(protocolv1.DeniedColumnNotAllowed, "column %q is not a retention column of %s", job.Predicate.Column, job.Target)
	}
	for _, column := range conditionColumns(job.Condition, job.Holds) {
		if !rule.allowsColumn(column) {
			return deny(protocolv1.DeniedColumnNotAllowed, "condition column %q is not a retention column of %s", column, job.Target)
		}
	}

	if decision, refused := s.checkCeilings(job, rule); refused {
		return decision
	}
	if decision, refused := s.checkApproval(job, now); refused {
		return decision
	}
	if decision, refused := s.checkDrift(job); refused {
		return decision
	}
	return allow(s.effectiveLimits(*job.Limits))
}

func conditionColumns(condition *protocolv1.Condition, holds []protocolv1.Condition) []string {
	columns := make([]string, 0, 8)
	var visit func(*protocolv1.Condition)
	visit = func(node *protocolv1.Condition) {
		if node == nil {
			return
		}
		if node.Column != "" {
			columns = append(columns, node.Column)
		}
		for index := range node.All {
			visit(&node.All[index])
		}
		for index := range node.Any {
			visit(&node.Any[index])
		}
		visit(node.Not)
	}
	visit(condition)
	for index := range holds {
		visit(&holds[index])
	}
	return columns
}

func (s *Safety) checkDrift(job *protocolv1.JobEnvelope) (Decision, bool) {
	if !job.Operation.Destructive() {
		return Decision{}, false
	}
	if job.Drift == nil {
		return deny(protocolv1.DeniedByLocalPolicy, "a destructive job arrived without a drift policy"), true
	}
	if s.Drift.Mode == "strict" || job.Drift.ExpectedRows < s.Drift.ExactMatchBelowRows {
		if job.Drift.MaxRows == 0 && job.Drift.MaxBasisPoints == 0 {
			return Decision{}, false
		}
		return deny(protocolv1.DeniedByLocalPolicy,
			"job permits drift where local policy requires an exact recount"), true
	}
	if job.Drift.MaxRows > s.Drift.MaxRows || job.Drift.MaxBasisPoints > s.Drift.MaxBasisPoints {
		return deny(protocolv1.DeniedByLocalPolicy,
			"job drift limits exceed the local maximum"), true
	}
	return Decision{}, false
}

// checkCeilings refuses — rather than silently lowering — a job that asks for more scope than
// the customer granted.
//
// Clamping would be friendlier and wrong. The plan a human approved said "up to 60 000 rows";
// quietly doing 50 000 executes an operation nobody approved and reports success for it. The
// operator must see the refusal and either raise the local ceiling deliberately or re-plan.
func (s *Safety) checkCeilings(job *protocolv1.JobEnvelope, rule *TableRule) (Decision, bool) {
	if maxRows := smallestPositive(rule.MaxDeleteRows, s.MaxDeleteRows); maxRows > 0 && job.Limits.MaxRows > maxRows {
		return deny(protocolv1.DeniedRowLimit, "job asks for %d rows on %s; local ceiling is %d",
			job.Limits.MaxRows, job.Target, maxRows), true
	}
	if maxBatch := smallestPositive(rule.MaxBatchSize, s.MaxBatchSize); maxBatch > 0 && job.Limits.BatchSize > maxBatch {
		return deny(protocolv1.DeniedBatchLimit, "job asks for batches of %d on %s; local ceiling is %d",
			job.Limits.BatchSize, job.Target, maxBatch), true
	}
	return Decision{}, false
}

func (s *Safety) checkApproval(job *protocolv1.JobEnvelope, now time.Time) (Decision, bool) {
	if !job.Operation.Destructive() || !s.RequireApproval {
		return Decision{}, false
	}
	if job.Approval == nil {
		return deny(protocolv1.DeniedApprovalRequired, "local policy requires an approval for %s", job.Operation), true
	}
	if !now.Before(job.Approval.ExpiresAt) {
		return deny(protocolv1.DeniedApprovalExpired, "approval %s expired at %s", job.Approval.ID, job.Approval.ExpiresAt.UTC().Format(time.RFC3339)), true
	}
	return Decision{}, false
}

// effectiveLimits lowers protective timeouts to the local maximum.
//
// Timeouts are the one class of limit that is clamped rather than refused, because they bound
// damage to the customer's database rather than the scope of the operation. A shorter statement
// timeout than requested can only make the job give up earlier.
func (s *Safety) effectiveLimits(requested protocolv1.Limits) protocolv1.Limits {
	effective := requested
	if s.StatementTimeoutSeconds > 0 {
		effective.StatementTimeoutSeconds = smallestPositive(effective.StatementTimeoutSeconds, s.StatementTimeoutSeconds)
	}
	if s.LockTimeoutSeconds > 0 {
		effective.LockTimeoutSeconds = smallestPositive(effective.LockTimeoutSeconds, s.LockTimeoutSeconds)
	}
	if s.MaxDurationSeconds > 0 {
		effective.MaxDurationSeconds = smallestPositive(effective.MaxDurationSeconds, s.MaxDurationSeconds)
	}
	return effective
}

// smallestPositive returns the tighter of two ceilings, treating zero as "not configured".
func smallestPositive(left, right int) int {
	switch {
	case left <= 0:
		return right
	case right <= 0:
		return left
	case left < right:
		return left
	default:
		return right
	}
}

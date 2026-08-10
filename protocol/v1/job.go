package protocolv1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// Operation is the closed set of things a control plane may ask for. Adding a member is a
// protocol version change and a security review, because each one is a new privilege granted
// to a remote party over a customer's database.
type Operation string

const (
	OpTestConnection Operation = "POSTGRES_TEST_CONNECTION"
	OpDiscover       Operation = "POSTGRES_DISCOVER"
	OpCount          Operation = "POSTGRES_COUNT"
	OpDelete         Operation = "POSTGRES_DELETE"
)

// Operations is the capability list a connector advertises. It exists as a slice so the
// heartbeat cannot claim something the switch statements do not implement.
var Operations = []Operation{OpTestConnection, OpDiscover, OpCount, OpDelete}

// Destructive reports whether an operation can remove customer data. Only one currently can,
// and the extra checks in the verifier and the local policy hang off this predicate.
func (o Operation) Destructive() bool { return o == OpDelete }

func (o Operation) known() bool {
	for _, candidate := range Operations {
		if candidate == o {
			return true
		}
	}
	return false
}

// PredicateType is the comparison a retention predicate may express. There is no NOT, no OR and
// no arbitrary operator: a retention rule is "older than a date", and anything richer belongs in
// the control plane's planner, not in a component holding delete rights.
type PredicateType string

const (
	PredicateBefore     PredicateType = "BEFORE"
	PredicateOnOrBefore PredicateType = "ON_OR_BEFORE"
)

// Target names a table. Both members are validated against Identifier before any query builder
// sees them.
type Target struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
}

func (t Target) String() string { return t.Schema + "." + t.Table }

// Predicate is one column, one comparison, one instant. The value is always bound as a query
// parameter; nothing in this struct is ever rendered into a statement.
type Predicate struct {
	Type   PredicateType `json:"type"`
	Column string        `json:"column"`
	Value  time.Time     `json:"value"`
}

// Condition is a closed declarative boolean tree. Exactly one of predicate, all, any or not is
// present. Values are JSON literals, never SQL fragments; the PostgreSQL adapter maps the closed
// operator set to parameterized expressions.
type Condition struct {
	Column   string          `json:"column,omitempty"`
	Operator string          `json:"operator,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	All      []Condition     `json:"all,omitempty"`
	Any      []Condition     `json:"any,omitempty"`
	Not      *Condition      `json:"not,omitempty"`
}

// Limits are ceilings requested by the control plane. The local safety policy may lower them and
// may never raise them, which is what keeps a compromised control plane from asking for more
// than the customer configured.
type Limits struct {
	BatchSize               int `json:"batch_size"`
	MaxRows                 int `json:"max_rows"`
	StatementTimeoutSeconds int `json:"statement_timeout_seconds"`
	LockTimeoutSeconds      int `json:"lock_timeout_seconds,omitempty"`
	MaxDurationSeconds      int `json:"max_duration_seconds,omitempty"`
	PauseBetweenBatchesMS   int `json:"pause_between_batches_ms,omitempty"`
}

// Drift carries what the plan measured so the connector can prove reality has not moved too far
// since. Without it, a plan approved on Monday would delete Wednesday's rows.
type Drift struct {
	ExpectedRows   int64 `json:"expected_rows"`
	MaxRows        int64 `json:"max_rows,omitempty"`
	MaxBasisPoints int   `json:"max_basis_points,omitempty"`
}

// Approval is the connector's own evidence that a human authorized this plan digest. It is
// checked locally, so the control plane cannot delete without one even against its own database.
type Approval struct {
	ID         string    `json:"id"`
	ApprovedAt time.Time `json:"approved_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// JobEnvelope is the complete instruction set. Compare it with what a generic remote-execution
// agent accepts: there is no statement, no script, no path and no host here, so the worst a
// stolen control-plane signing key can express is an operation this connector already
// implements against a target the customer already allow-listed.
type JobEnvelope struct {
	ProtocolVersion string    `json:"protocol_version"`
	JobID           string    `json:"job_id"`
	OrganizationID  string    `json:"organization_id"`
	ConnectorID     string    `json:"connector_id"`
	DataSourceID    string    `json:"data_source_id"`
	Operation       Operation `json:"operation"`

	Target     *Target     `json:"target,omitempty"`
	Predicate  *Predicate  `json:"predicate,omitempty"`
	Condition  *Condition  `json:"condition,omitempty"`
	Holds      []Condition `json:"holds,omitempty"`
	Limits     *Limits     `json:"limits,omitempty"`
	Drift      *Drift      `json:"drift,omitempty"`
	PlanDigest string      `json:"plan_digest,omitempty"`
	Approval   *Approval   `json:"approval,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce     string    `json:"nonce"`
	Signature string    `json:"signature"`
}

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifierPattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	signaturePattern  = regexp.MustCompile(`^ed25519:[A-Za-z0-9+/]{86}==$`)
	noncePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
)

// IsIdentifier reports whether name is an unquoted lowercase PostgreSQL identifier.
//
// This is the single gate every schema, table and column name passes before the SQL builder is
// allowed to see it. Keeping it here — in the protocol package, next to the type it validates —
// means a new adapter cannot accidentally introduce a second, looser definition.
func IsIdentifier(name string) bool { return identifierPattern.MatchString(name) }

// IsDigest reports whether value has the "sha256:<64 hex>" shape used throughout the protocol.
func IsDigest(value string) bool { return digestPattern.MatchString(value) }

// DecodeJob parses raw as a job envelope, refusing unknown members.
//
// Strict decoding is a security control, not tidiness: it is how "additionalProperties: false"
// in the schema becomes true at runtime. A control plane that grew a new field the connector
// does not understand is refused rather than silently obeyed in part.
func DecodeJob(raw []byte) (*JobEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var job JobEnvelope
	if err := decoder.Decode(&job); err != nil {
		return nil, fmt.Errorf("protocol: job is not valid v1: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("protocol: trailing content after job envelope")
	}
	return &job, nil
}

// Validate checks the envelope's shape only: identity formats, closed enums, member presence
// and numeric ceilings. It answers "is this a well-formed v1 job", never "may this connector run
// it" — that question belongs to the local safety policy, and keeping the two apart is what lets
// each be tested exhaustively on its own.
func (j *JobEnvelope) Validate() error {
	if j.ProtocolVersion != Version {
		return fmt.Errorf("protocol: unsupported version %q", j.ProtocolVersion)
	}
	for name, value := range map[string]string{
		"job_id":          j.JobID,
		"organization_id": j.OrganizationID,
		"connector_id":    j.ConnectorID,
		"data_source_id":  j.DataSourceID,
	} {
		if !uuidPattern.MatchString(value) {
			return fmt.Errorf("protocol: %s is not a lowercase UUID", name)
		}
	}
	if !j.Operation.known() {
		return fmt.Errorf("protocol: unknown operation %q", j.Operation)
	}
	if !noncePattern.MatchString(j.Nonce) {
		return fmt.Errorf("protocol: nonce is malformed")
	}
	if !signaturePattern.MatchString(j.Signature) {
		return fmt.Errorf("protocol: signature is malformed")
	}
	if j.IssuedAt.IsZero() || j.ExpiresAt.IsZero() {
		return fmt.Errorf("protocol: issued_at and expires_at are required")
	}
	if !j.ExpiresAt.After(j.IssuedAt) {
		return fmt.Errorf("protocol: expires_at must follow issued_at")
	}
	if err := j.validateOperands(); err != nil {
		return err
	}
	return j.validateDestructiveOperands()
}

func (j *JobEnvelope) validateOperands() error {
	needsTarget := j.Operation == OpCount || j.Operation == OpDelete
	if !needsTarget {
		return nil
	}
	if j.Target == nil || j.Predicate == nil || j.Limits == nil {
		return fmt.Errorf("protocol: %s requires target, predicate and limits", j.Operation)
	}
	if !IsIdentifier(j.Target.Schema) || !IsIdentifier(j.Target.Table) {
		return fmt.Errorf("protocol: target is not a pair of plain identifiers")
	}
	if !IsIdentifier(j.Predicate.Column) {
		return fmt.Errorf("protocol: predicate column is not a plain identifier")
	}
	switch j.Predicate.Type {
	case PredicateBefore, PredicateOnOrBefore:
	default:
		return fmt.Errorf("protocol: unknown predicate type %q", j.Predicate.Type)
	}
	if j.Predicate.Value.IsZero() {
		return fmt.Errorf("protocol: predicate value is required")
	}
	budget := 0
	if j.Condition != nil {
		if err := j.Condition.validate(&budget, 0); err != nil {
			return err
		}
	}
	if len(j.Holds) == 0 {
		return fmt.Errorf("protocol: %s requires at least one hold condition", j.Operation)
	}
	for index := range j.Holds {
		if err := j.Holds[index].validate(&budget, 0); err != nil {
			return err
		}
	}
	return j.Limits.validate()
}

func (c *Condition) validate(budget *int, depth int) error {
	(*budget)++
	if *budget > 500 || depth > 16 {
		return fmt.Errorf("protocol: condition tree exceeds its complexity budget")
	}
	forms := 0
	if c.Column != "" || c.Operator != "" || len(c.Value) > 0 {
		forms++
	}
	if len(c.All) > 0 {
		forms++
	}
	if len(c.Any) > 0 {
		forms++
	}
	if c.Not != nil {
		forms++
	}
	if forms != 1 {
		return fmt.Errorf("protocol: condition must contain exactly one form")
	}
	if c.Column != "" || c.Operator != "" || len(c.Value) > 0 {
		return c.validatePredicate()
	}
	children := c.All
	if len(c.Any) > 0 {
		children = c.Any
	}
	if len(children) > 100 {
		return fmt.Errorf("protocol: condition group is too large")
	}
	for index := range children {
		if err := children[index].validate(budget, depth+1); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.validate(budget, depth+1)
	}
	return nil
}

func (c *Condition) validatePredicate() error {
	if !IsIdentifier(c.Column) {
		return fmt.Errorf("protocol: condition column is not a plain identifier")
	}
	valueless := c.Operator == "isNull" || c.Operator == "isNotNull" || c.Operator == "beforeCutoff" || c.Operator == "afterCutoff"
	sequence := c.Operator == "in" || c.Operator == "notIn"
	switch c.Operator {
	case "eq", "neq", "lt", "lte", "gt", "gte", "in", "notIn", "isNull", "isNotNull", "beforeCutoff", "afterCutoff":
	default:
		return fmt.Errorf("protocol: unknown condition operator %q", c.Operator)
	}
	if valueless && len(c.Value) > 0 {
		return fmt.Errorf("protocol: condition operator %s accepts no value", c.Operator)
	}
	if !valueless && len(c.Value) == 0 {
		return fmt.Errorf("protocol: condition operator %s requires a value", c.Operator)
	}
	if len(c.Value) == 0 {
		return nil
	}
	value, err := DecodeConditionValue(c.Value)
	if err != nil {
		return err
	}
	items, isSequence := value.([]any)
	if sequence && (!isSequence || len(items) == 0 || len(items) > 100) {
		return fmt.Errorf("protocol: %s requires between 1 and 100 values", c.Operator)
	}
	if !sequence && isSequence {
		return fmt.Errorf("protocol: %s requires a scalar value", c.Operator)
	}
	return nil
}

// DecodeConditionValue parses one already-validated literal without converting integers to
// floats. It is exported for adapters; accepting any richer type there would widen the protocol.
func DecodeConditionValue(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("protocol: condition value is invalid: %w", err)
	}
	return normalizeConditionValue(value)
}

func normalizeConditionValue(value any) (any, error) {
	switch typed := value.(type) {
	case string, bool:
		return typed, nil
	case json.Number:
		if bytes.ContainsAny([]byte(typed.String()), ".eE") {
			return nil, fmt.Errorf("protocol: condition values cannot contain floats")
		}
		integer, err := typed.Int64()
		if err != nil {
			return nil, fmt.Errorf("protocol: condition integer is out of range")
		}
		return integer, nil
	case []any:
		values := make([]any, 0, len(typed))
		for _, item := range typed {
			normalized, err := normalizeConditionValue(item)
			if err != nil {
				return nil, err
			}
			if _, nested := normalized.([]any); nested {
				return nil, fmt.Errorf("protocol: nested condition values are not supported")
			}
			values = append(values, normalized)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("protocol: condition value has unsupported type %T", value)
	}
}

func (j *JobEnvelope) validateDestructiveOperands() error {
	if !j.Operation.Destructive() {
		return nil
	}
	if !IsDigest(j.PlanDigest) {
		return fmt.Errorf("protocol: %s requires a plan digest", j.Operation)
	}
	if j.Drift == nil {
		return fmt.Errorf("protocol: %s requires a drift policy", j.Operation)
	}
	if err := j.Drift.validate(); err != nil {
		return err
	}
	if j.Approval == nil {
		return fmt.Errorf("protocol: %s requires an approval", j.Operation)
	}
	if !uuidPattern.MatchString(j.Approval.ID) {
		return fmt.Errorf("protocol: approval id is not a lowercase UUID")
	}
	if j.Approval.ApprovedAt.IsZero() || j.Approval.ExpiresAt.IsZero() {
		return fmt.Errorf("protocol: approval is missing its validity window")
	}
	if !j.Approval.ExpiresAt.After(j.Approval.ApprovedAt) {
		return fmt.Errorf("protocol: approval expires before it was granted")
	}
	return nil
}

func (d *Drift) validate() error {
	switch {
	case d.ExpectedRows < 0 || d.ExpectedRows > 100_000_000:
		return fmt.Errorf("protocol: drift expected_rows out of range")
	case d.MaxRows < 0 || d.MaxRows > 100_000_000:
		return fmt.Errorf("protocol: drift max_rows out of range")
	case d.MaxBasisPoints < 0 || d.MaxBasisPoints > 10_000:
		return fmt.Errorf("protocol: drift max_basis_points out of range")
	}
	return nil
}

func (l *Limits) validate() error {
	switch {
	case l.BatchSize < 1 || l.BatchSize > 50000:
		return fmt.Errorf("protocol: batch_size out of range")
	case l.MaxRows < 1 || l.MaxRows > 100_000_000:
		return fmt.Errorf("protocol: max_rows out of range")
	case l.StatementTimeoutSeconds < 1 || l.StatementTimeoutSeconds > 3600:
		return fmt.Errorf("protocol: statement_timeout_seconds out of range")
	case l.LockTimeoutSeconds < 0 || l.LockTimeoutSeconds > 600:
		return fmt.Errorf("protocol: lock_timeout_seconds out of range")
	case l.MaxDurationSeconds < 0 || l.MaxDurationSeconds > 86400:
		return fmt.Errorf("protocol: max_duration_seconds out of range")
	case l.PauseBetweenBatchesMS < 0 || l.PauseBetweenBatchesMS > 60000:
		return fmt.Errorf("protocol: pause_between_batches_ms out of range")
	case l.BatchSize > l.MaxRows:
		return fmt.Errorf("protocol: batch_size exceeds max_rows")
	}
	return nil
}

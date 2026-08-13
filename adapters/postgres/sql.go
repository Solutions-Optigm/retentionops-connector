// Package postgres is the only code in the connector that talks to a customer's database.
//
// Every statement it can emit is written out in this file. There is no template engine, no
// string concatenation of caller-supplied fragments, and no code path that accepts SQL from the
// network — which is what makes "RetentionOps cannot run arbitrary SQL against your database" an
// auditable claim rather than a policy statement.
package postgres

import (
	"fmt"
	"strings"

	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
)

// quoteIdentifier renders a validated identifier for inclusion in a statement.
//
// The argument has already passed protocolv1.IsIdentifier — twice, in the protocol validator and
// in the local safety policy — so it contains no quote character and cannot escape the quoting.
// The quotes are applied anyway so that a name colliding with a reserved word behaves, and the
// panic is here because reaching this function with an unvalidated name would be a programming
// error that must not degrade into a query.
func quoteIdentifier(name string) string {
	if !protocolv1.IsIdentifier(name) {
		panic("postgres: refusing to quote an unvalidated identifier")
	}
	return `"` + name + `"`
}

func qualified(target protocolv1.Target) string {
	return quoteIdentifier(target.Schema) + "." + quoteIdentifier(target.Table)
}

// comparison renders the one operator a retention predicate may use.
func comparison(kind protocolv1.PredicateType) string {
	if kind == protocolv1.PredicateOnOrBefore {
		return "<="
	}
	return "<"
}

// countStatement measures the candidate set without reading a single row of it.
//
// It returns a count and the boundary timestamps, because those three numbers are what a plan
// needs and what evidence records. Nothing here can return a row value.
func countStatement(
	target protocolv1.Target,
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
) (string, []any, error) {
	column := quoteIdentifier(predicate.Column)
	where, arguments, err := candidateWhere(predicate, condition, holds)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf(
		"SELECT count(*)::bigint, min(%s), max(%s) FROM %s WHERE %s",
		column, column, qualified(target), where,
	), arguments, nil
}

// sizeStatement estimates the bytes the candidate set occupies.
//
// Deliberately an estimate from the planner's own statistics rather than a sum over the rows: an
// exact figure would mean scanning every candidate row's contents, which is both expensive on a
// production table and the one thing this connector is built never to do.
const sizeStatement = `SELECT pg_total_relation_size(c.oid)::bigint,
                              GREATEST(c.reltuples, 0)::bigint
                         FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = $1 AND c.relname = $2`

// deleteBatchStatement removes at most one batch, addressing rows by physical location.
//
// ctid rather than a primary key keeps the statement identical for tables without one. The
// eligibility predicate is repeated on the DELETE so a concurrent change is rechecked after a
// lock wait. PostgreSQL requires UPDATE privilege for every SKIP LOCKED row-lock mode; bounded
// lock_timeout is safer than granting a deletion identity the ability to update customer rows.
func deleteBatchStatement(
	target protocolv1.Target,
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
) (string, []any, error) {
	table := qualified(target)
	column := quoteIdentifier(predicate.Column)
	where, arguments, err := candidateWhere(predicate, condition, holds)
	if err != nil {
		return "", nil, err
	}
	batchPlaceholder := fmt.Sprintf("$%d", len(arguments)+1)
	return fmt.Sprintf(`WITH doomed AS (
	    SELECT ctid FROM %s
	     WHERE %s
	     ORDER BY %s
	     LIMIT %s
	)
	DELETE FROM %s
	 WHERE ctid IN (SELECT ctid FROM doomed)
	   AND %s`,
		table, where, column, batchPlaceholder, table, where), arguments, nil
}

func candidateWhere(
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
) (string, []any, error) {
	parts, arguments, err := eligibilityWhere(predicate, condition)
	if err != nil {
		return "", nil, err
	}
	holdClauses, err := compileConditions(holds, &arguments)
	if err != nil {
		return "", nil, err
	}
	if len(holdClauses) > 0 {
		parts = append(parts, "NOT ("+strings.Join(holdClauses, " OR ")+")")
	}
	return strings.Join(parts, " AND "), arguments, nil
}

func heldCountStatement(
	target protocolv1.Target,
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
) (string, []any, error) {
	parts, arguments, err := eligibilityWhere(predicate, condition)
	if err != nil {
		return "", nil, err
	}
	holdClauses, err := compileConditions(holds, &arguments)
	if err != nil {
		return "", nil, err
	}
	parts = append(parts, "("+strings.Join(holdClauses, " OR ")+")")
	return fmt.Sprintf("SELECT count(*)::bigint FROM %s WHERE %s", qualified(target), strings.Join(parts, " AND ")), arguments, nil
}

func resourceCountStatement(target protocolv1.Target) string {
	return fmt.Sprintf("SELECT count(*)::bigint FROM %s", qualified(target))
}

func eligibilityWhere(
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
) ([]string, []any, error) {
	arguments := []any{predicate.Value}
	parts := []string{fmt.Sprintf("%s %s $1", quoteIdentifier(predicate.Column), comparison(predicate.Type))}
	if condition != nil {
		clause, err := compileCondition(condition, &arguments)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, "("+clause+")")
	}
	return parts, arguments, nil
}

func compileConditions(conditions []protocolv1.Condition, arguments *[]any) ([]string, error) {
	holdClauses := make([]string, 0, len(conditions))
	for index := range conditions {
		clause, err := compileCondition(&conditions[index], arguments)
		if err != nil {
			return nil, err
		}
		holdClauses = append(holdClauses, "("+clause+")")
	}
	return holdClauses, nil
}

func compileCondition(condition *protocolv1.Condition, arguments *[]any) (string, error) {
	if condition.Column != "" {
		return compilePredicate(condition, arguments)
	}
	children := condition.All
	joiner := " AND "
	if len(condition.Any) > 0 {
		children = condition.Any
		joiner = " OR "
	}
	if condition.Not != nil {
		child, err := compileCondition(condition.Not, arguments)
		return "NOT (" + child + ")", err
	}
	clauses := make([]string, 0, len(children))
	for index := range children {
		clause, err := compileCondition(&children[index], arguments)
		if err != nil {
			return "", err
		}
		clauses = append(clauses, "("+clause+")")
	}
	return strings.Join(clauses, joiner), nil
}

func compilePredicate(condition *protocolv1.Condition, arguments *[]any) (string, error) {
	column := quoteIdentifier(condition.Column)
	switch condition.Operator {
	case "isNull":
		return column + " IS NULL", nil
	case "isNotNull":
		return column + " IS NOT NULL", nil
	case "beforeCutoff":
		return column + " < $1", nil
	case "afterCutoff":
		return column + " >= $1", nil
	}
	value, err := protocolv1.DecodeConditionValue(condition.Value)
	if err != nil {
		return "", err
	}
	if values, sequence := value.([]any); sequence {
		placeholders := make([]string, 0, len(values))
		for _, item := range values {
			*arguments = append(*arguments, item)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(*arguments)))
		}
		operator := "IN"
		if condition.Operator == "notIn" {
			operator = "NOT IN"
		}
		return fmt.Sprintf("%s %s (%s)", column, operator, strings.Join(placeholders, ", ")), nil
	}
	operators := map[string]string{"eq": "=", "neq": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
	operator, known := operators[condition.Operator]
	if !known {
		return "", fmt.Errorf("postgres: unsupported condition operator %q", condition.Operator)
	}
	*arguments = append(*arguments, value)
	return fmt.Sprintf("%s %s $%d", column, operator, len(*arguments)), nil
}

// discoverStatement lists structure for the schemas the customer allow-listed, and only those.
//
// The schema filter is applied in the database rather than in Go: a connector scoped to one
// schema must not pull the rest of the catalogue across the wire and then discard it.
const discoverStatement = `SELECT c.table_schema,
                                  c.table_name,
                                  c.column_name,
                                  c.data_type,
                                  c.is_nullable = 'YES',
                                  COALESCE(k.is_primary, false)
                             FROM information_schema.columns c
                             LEFT JOIN (
                                  SELECT kcu.table_schema, kcu.table_name, kcu.column_name, true AS is_primary
                                    FROM information_schema.table_constraints tc
                                    JOIN information_schema.key_column_usage kcu
                                      ON kcu.constraint_name = tc.constraint_name
                                     AND kcu.table_schema = tc.table_schema
                                   WHERE tc.constraint_type = 'PRIMARY KEY'
                             ) k ON k.table_schema = c.table_schema
                                AND k.table_name = c.table_name
                                AND k.column_name = c.column_name
                            WHERE c.table_schema::text = ANY($1::text[])
                            ORDER BY c.table_schema, c.table_name, c.ordinal_position`

// referenceStatement lists the foreign keys declared between allow-listed schemas.
//
// It reads pg_catalog rather than information_schema.referential_constraints because only the
// catalogue preserves the pairing of a composite key. information_schema exposes the two sides
// through separate views with no shared ordinal, so a two-column key there yields four plausible
// pairs and no way to tell which two are real. unnest(conkey, confkey) WITH ORDINALITY walks both
// arrays in step, which is the pairing the database itself stores.
//
// Both ends are filtered to the allow-listed schemas. A key pointing out of the perimeter is not
// reported at all: naming a table the customer deliberately left out of scope would disclose its
// existence, which is precisely what allow-listing a schema is meant to prevent.
const referenceStatement = `SELECT source_namespace.nspname,
                                   source_relation.relname,
                                   source_attribute.attname,
                                   target_namespace.nspname,
                                   target_relation.relname,
                                   target_attribute.attname
                              FROM pg_constraint constraint_row
                              JOIN pg_class source_relation
                                ON source_relation.oid = constraint_row.conrelid
                              JOIN pg_namespace source_namespace
                                ON source_namespace.oid = source_relation.relnamespace
                              JOIN pg_class target_relation
                                ON target_relation.oid = constraint_row.confrelid
                              JOIN pg_namespace target_namespace
                                ON target_namespace.oid = target_relation.relnamespace
                              JOIN LATERAL unnest(constraint_row.conkey, constraint_row.confkey)
                                        WITH ORDINALITY AS key_pair(source_attnum, target_attnum, ordinality)
                                ON true
                              JOIN pg_attribute source_attribute
                                ON source_attribute.attrelid = source_relation.oid
                               AND source_attribute.attnum = key_pair.source_attnum
                              JOIN pg_attribute target_attribute
                                ON target_attribute.attrelid = target_relation.oid
                               AND target_attribute.attnum = key_pair.target_attnum
                             WHERE constraint_row.contype = 'f'
                               AND source_namespace.nspname::text = ANY($1::text[])
                               AND target_namespace.nspname::text = ANY($1::text[])
                             ORDER BY source_namespace.nspname,
                                      source_relation.relname,
                                      key_pair.ordinality`

// versionStatement is the only thing a connection test reads.
//
// pg_stat_ssl is consulted rather than the server's `ssl` setting: the question is whether *this
// connection* is encrypted, not whether the server would have allowed one that is. A role can
// always see its own backend's row.
const versionStatement = `SELECT current_setting('server_version'),
                                 COALESCE((SELECT s.ssl FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()), false)`

// timeoutStatements bound a transaction.
//
// These interpolate integers rather than binding parameters because PostgreSQL's SET does not
// accept a bound parameter. The values arrive from protocolv1.Limits, which validates them as
// integers inside a fixed range before any of this runs, so the interpolation cannot carry
// anything but digits.
func timeoutStatements(limits protocolv1.Limits) []string {
	statements := []string{
		fmt.Sprintf("SET LOCAL statement_timeout = %d", limits.StatementTimeoutSeconds*1000),
		// idle_in_transaction_session_timeout protects the customer from us: a connector that
		// stalls mid-batch must not hold locks indefinitely on a production table.
		fmt.Sprintf("SET LOCAL idle_in_transaction_session_timeout = %d", limits.StatementTimeoutSeconds*1000),
	}
	if limits.LockTimeoutSeconds > 0 {
		statements = append(statements, fmt.Sprintf("SET LOCAL lock_timeout = %d", limits.LockTimeoutSeconds*1000))
	}
	return statements
}

// dsn builds a libpq keyword/value connection string with no password in it.
//
// The password is set on the parsed configuration afterwards, so it never exists as part of a
// string that could be logged, appear in an error, or be captured by a crash handler.
func dsn(host string, port int, database, user, sslMode, caFile string, connectTimeout int) string {
	pairs := []string{
		"host=" + quoteValue(host),
		fmt.Sprintf("port=%d", port),
		"dbname=" + quoteValue(database),
		"user=" + quoteValue(user),
		"sslmode=" + quoteValue(sslMode),
		fmt.Sprintf("connect_timeout=%d", connectTimeout),
		"application_name=" + quoteValue("retentionops-connector"),
	}
	if caFile != "" {
		pairs = append(pairs, "sslrootcert="+quoteValue(caFile))
	}
	return strings.Join(pairs, " ")
}

func quoteValue(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
	return "'" + escaped + "'"
}

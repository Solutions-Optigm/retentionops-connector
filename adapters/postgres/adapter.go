package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/solutions-optigm/retentionops-connector/internal/config"
	protocolv1 "github.com/solutions-optigm/retentionops-connector/protocol/v1"
	"github.com/solutions-optigm/retentionops-connector/secrets"
)

// Role is which of the two configured PostgreSQL identities a piece of work runs as.
type Role string

const (
	// RoleReader plans and measures. It should hold SELECT and nothing else.
	RoleReader Role = "reader"
	// RoleExecutor deletes. It should hold SELECT and DELETE on the allow-listed tables and
	// nothing else, and it is resolved only on the destructive path.
	RoleExecutor Role = "executor"
)

const connectTimeoutSeconds = 10

// Adapter runs the four PostgreSQL operations against one configured source.
type Adapter struct {
	id      string
	source  *config.Source
	secrets *secrets.Registry
	log     *slog.Logger
}

// New builds an adapter for one data source.
func New(id string, source *config.Source, registry *secrets.Registry, log *slog.Logger) *Adapter {
	return &Adapter{id: id, source: source, secrets: registry, log: log}
}

// connect opens a connection as one of the two identities.
//
// The executor's secret is resolved here and nowhere else, which is what gives the two-identity
// design its value: a flaw anywhere in the planning path cannot obtain the destructive
// credential, because on that path the credential is never fetched at all.
func (a *Adapter) connect(ctx context.Context, role Role) (*pgx.Conn, error) {
	credential := a.source.Reader
	if role == RoleExecutor {
		credential = a.source.Executor
	}
	password, err := a.secrets.Resolve(ctx, credential.Password.Provider, credential.Password.Ref)
	if err != nil {
		return nil, &OperationError{Code: protocolv1.FailureSecret, err: err}
	}
	settings, err := pgx.ParseConfig(dsn(
		a.source.Host, a.source.Port, a.source.Database, credential.Username,
		a.source.TLS.Mode, a.source.TLS.CAFile, connectTimeoutSeconds,
	))
	if err != nil {
		return nil, &OperationError{Code: protocolv1.FailureInternal, err: err}
	}
	settings.Password = string(password)
	connection, err := pgx.ConnectConfig(ctx, settings)
	if err != nil {
		return nil, classify(err)
	}
	return connection, nil
}

// OperationError carries the stable failure class alongside the local detail.
//
// The class travels to the control plane; the wrapped error stays in the customer's own logs. A
// PostgreSQL error message can quote a row value, which is exactly why it is never forwarded.
type OperationError struct {
	Code protocolv1.FailureCode
	err  error
}

func (e *OperationError) Error() string { return string(e.Code) + ": " + e.err.Error() }
func (e *OperationError) Unwrap() error { return e.err }

// Classify maps an error to the stable failure class the protocol carries.
func Classify(err error) protocolv1.FailureCode {
	var operational *OperationError
	if errors.As(err, &operational) {
		return operational.Code
	}
	return protocolv1.FailureInternal
}

func classify(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "57014":
			return &OperationError{Code: protocolv1.FailureStatementTimeout, err: err}
		case "55P03":
			return &OperationError{Code: protocolv1.FailureLockTimeout, err: err}
		case "42501":
			return &OperationError{Code: protocolv1.FailurePermission, err: err}
		case "42P01", "42703", "3D000":
			return &OperationError{Code: protocolv1.FailureTargetChanged, err: err}
		}
		if len(pgErr.Code) == 5 && pgErr.Code[:2] == "28" {
			return &OperationError{Code: protocolv1.FailureAuthentication, err: err}
		}
	}
	// A certificate that does not chain, or a name that does not match, is reported as its own
	// class: "cannot reach the database" and "reached something that could not prove it is the
	// database" are different incidents and lead to different fixes.
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &verification) || errors.As(err, &authority) || errors.As(err, &hostname) {
		return &OperationError{Code: protocolv1.FailureTLS, err: err}
	}
	return &OperationError{Code: protocolv1.FailureUnreachable, err: err}
}

// TestConnection proves the source is reachable, encrypted and usable by both identities.
//
// It reads a version string and one boolean. Nothing about the customer's data is touched, which
// is why this operation needs no target and no allow-list entry.
func (a *Adapter) TestConnection(ctx context.Context) (*protocolv1.Statistics, error) {
	statistics := &protocolv1.Statistics{TLSMode: a.source.TLS.Mode}

	reader, err := a.connect(ctx, RoleReader)
	if err != nil {
		return nil, err
	}
	defer reader.Close(context.WithoutCancel(ctx))

	var version string
	var encrypted bool
	if err := reader.QueryRow(ctx, versionStatement).Scan(&version, &encrypted); err != nil {
		return nil, classify(err)
	}
	if !encrypted && a.source.TLS.Mode != config.TLSRequire {
		return nil, &OperationError{
			Code: protocolv1.FailureTLS,
			err:  errors.New("the session is not encrypted although tls.mode demands it"),
		}
	}
	statistics.DatabaseVersion = version
	statistics.ReaderValidated = true

	if a.source.Safety.GrantsDelete() {
		executor, err := a.connect(ctx, RoleExecutor)
		if err != nil {
			// The reader worked, so the source is reachable; report the partial truth rather
			// than pretending the whole test failed.
			a.log.Warn("executor identity failed validation", "data_source_id", a.id, "error", err)
			return statistics, nil
		}
		defer executor.Close(context.WithoutCancel(ctx))
		statistics.ExecutorValidated = true
	}
	return statistics, nil
}

// Discover reports the structure of the allow-listed schemas: names, types, key membership and
// a row estimate. It never reads a value.
func (a *Adapter) Discover(ctx context.Context) (*protocolv1.Statistics, error) {
	reader, err := a.connect(ctx, RoleReader)
	if err != nil {
		return nil, err
	}
	defer reader.Close(context.WithoutCancel(ctx))

	rows, err := reader.Query(ctx, discoverStatement, a.source.Safety.AllowedSchemas)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	tables := make([]protocolv1.Table, 0, 32)
	index := make(map[string]int, 32)
	for rows.Next() {
		var schema, table, column, dataType string
		var nullable, primary bool
		if err := rows.Scan(&schema, &table, &column, &dataType, &nullable, &primary); err != nil {
			return nil, classify(err)
		}
		key := schema + "." + table
		position, seen := index[key]
		if !seen {
			tables = append(tables, protocolv1.Table{Schema: schema, Table: table})
			position = len(tables) - 1
			index[key] = position
		}
		tables[position].Columns = append(tables[position].Columns, protocolv1.Column{
			Name: column, Type: dataType, Nullable: nullable, PrimaryKey: primary,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, classify(err)
	}
	return &protocolv1.Statistics{Tables: tables}, nil
}

// Count measures the candidate set for a retention predicate.
//
// The whole transaction is read-only and bounded by a statement timeout, so the worst a
// pathological predicate can do to a production database is occupy one connection until the
// timeout fires.
func (a *Adapter) Count(
	ctx context.Context,
	target protocolv1.Target,
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
	limits protocolv1.Limits,
) (*protocolv1.Statistics, error) {
	reader, err := a.connect(ctx, RoleReader)
	if err != nil {
		return nil, err
	}
	defer reader.Close(context.WithoutCancel(ctx))

	transaction, err := reader.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, classify(err)
	}
	defer transaction.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read-only rollback

	// pgx.ReadOnly already opened this as BEGIN READ ONLY, so the transaction is physically
	// incapable of writing regardless of what the reader role was granted. Only the timeouts
	// remain to be set.
	for _, statement := range timeoutStatements(limits) {
		if _, err := transaction.Exec(ctx, statement); err != nil {
			return nil, classify(err)
		}
	}

	statistics := &protocolv1.Statistics{}
	var oldest, newest *time.Time
	statement, arguments, err := countStatement(target, predicate, condition, holds)
	if err != nil {
		return nil, err
	}
	err = transaction.QueryRow(ctx, statement, arguments...).
		Scan(&statistics.CandidateRows, &oldest, &newest)
	if err != nil {
		return nil, classify(err)
	}
	statistics.Oldest, statistics.Newest = oldest, newest
	statistics.ObservedRows = statistics.CandidateRows
	if err := transaction.QueryRow(ctx, resourceCountStatement(target)).Scan(&statistics.ResourceRows); err != nil {
		return nil, classify(err)
	}
	heldStatement, heldArguments, err := heldCountStatement(target, predicate, condition, holds)
	if err != nil {
		return nil, err
	}
	if err := transaction.QueryRow(ctx, heldStatement, heldArguments...).Scan(&statistics.BlockedHoldRows); err != nil {
		return nil, classify(err)
	}

	var totalBytes, liveRows int64
	if err := transaction.QueryRow(ctx, sizeStatement, target.Schema, target.Table).
		Scan(&totalBytes, &liveRows); err == nil && liveRows > 0 {
		statistics.EstimatedBytes = totalBytes * statistics.CandidateRows / liveRows
	}
	return statistics, nil
}

// BatchObserver is notified after every committed batch. The connector uses it to emit a job
// event, so a process killed mid-run still leaves an accurate record of what was removed.
type BatchObserver func(affected int64, cumulative int64, elapsed time.Duration) error

// Delete removes the candidate set in committed batches.
//
// One transaction per batch, never one transaction for the job. A single DELETE over millions of
// rows holds locks for its whole duration, produces a WAL burst the customer did not plan for,
// and gives back nothing if it is interrupted at 99 %. Batching costs a little throughput and
// buys interruptibility, bounded lock time, and a record of exactly what was already removed.
func (a *Adapter) Delete(
	ctx context.Context,
	target protocolv1.Target,
	predicate protocolv1.Predicate,
	condition *protocolv1.Condition,
	holds []protocolv1.Condition,
	limits protocolv1.Limits,
	observe BatchObserver,
) (*protocolv1.Statistics, bool, error) {
	executor, err := a.connect(ctx, RoleExecutor)
	if err != nil {
		return nil, false, err
	}
	defer executor.Close(context.WithoutCancel(ctx))

	statement, arguments, err := deleteBatchStatement(target, predicate, condition, holds)
	if err != nil {
		return nil, false, err
	}
	statistics := &protocolv1.Statistics{}
	complete := false
	activeStarted := time.Now()

	for statistics.RowsDeleted < int64(limits.MaxRows) {
		remaining := int64(limits.MaxRows) - statistics.RowsDeleted
		size := int64(limits.BatchSize)
		if remaining < size {
			// The final batch is trimmed so the job can never exceed the approved ceiling by
			// up to one batch. Ceilings that are "approximately" respected are not ceilings.
			size = remaining
		}
		batchArguments := append(append([]any{}, arguments...), size)
		affected, elapsed, err := a.deleteOneBatch(ctx, executor, statement, batchArguments, limits)
		if err != nil {
			return statistics, false, err
		}
		if affected == 0 {
			complete = true
			break
		}
		statistics.RowsDeleted += affected
		statistics.Batches++
		if observe != nil {
			checkpointStarted := time.Now()
			if err := observe(affected, statistics.RowsDeleted, elapsed); err != nil {
				return statistics, false, err
			}
			// Operator pause time is not database execution time. Moving the origin forward
			// preserves the approved active-duration ceiling across an arbitrarily long pause.
			activeStarted = activeStarted.Add(time.Since(checkpointStarted))
		}
		if limits.MaxDurationSeconds > 0 && time.Since(activeStarted) >= time.Duration(limits.MaxDurationSeconds)*time.Second {
			// A duration ceiling stops only between committed batches. Returning PARTIAL keeps
			// everything already committed truthful and avoids turning a bounded stop into a
			// misleading operational failure.
			break
		}
		if limits.PauseBetweenBatchesMS > 0 {
			delay := time.NewTimer(time.Duration(limits.PauseBetweenBatchesMS) * time.Millisecond)
			select {
			case <-ctx.Done():
				delay.Stop()
				return statistics, false, ctx.Err()
			case <-delay.C:
			}
		}
	}
	return statistics, complete, nil
}

func (a *Adapter) deleteOneBatch(
	ctx context.Context,
	executor *pgx.Conn,
	statement string,
	arguments []any,
	limits protocolv1.Limits,
) (int64, time.Duration, error) {
	started := time.Now()
	transaction, err := executor.Begin(ctx)
	if err != nil {
		return 0, 0, classify(err)
	}
	// Rollback after a successful commit is a documented no-op in pgx, so this defer is safe and
	// guarantees an early return can never leave the transaction open.
	defer transaction.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck

	for _, timeout := range timeoutStatements(limits) {
		if _, err := transaction.Exec(ctx, timeout); err != nil {
			return 0, 0, classify(err)
		}
	}
	tag, err := transaction.Exec(ctx, statement, arguments...)
	if err != nil {
		return 0, 0, classify(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return 0, 0, classify(err)
	}
	return tag.RowsAffected(), time.Since(started), nil
}

// Describe is used in log lines and in `doctor` output.
func (a *Adapter) Describe() string { return a.source.Describe() }

// Fingerprint identifies the source in telemetry without naming the customer's infrastructure.
func (a *Adapter) Fingerprint() string { return fmt.Sprintf("source=%s", a.id) }

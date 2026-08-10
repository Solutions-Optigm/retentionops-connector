# PostgreSQL

## Two roles

Create both. The connector uses them on different code paths and resolves their secrets at
different times, so the separation is real in this process and not only in the database.

```sql
-- Plans, counts, discovers. Never writes.
CREATE ROLE retentionops_reader LOGIN PASSWORD :'reader_password';
GRANT CONNECT ON DATABASE production TO retentionops_reader;
GRANT USAGE ON SCHEMA application TO retentionops_reader;
GRANT SELECT ON application.audit_logs TO retentionops_reader;

-- Deletes, and only from the tables you allow-list in the connector configuration.
CREATE ROLE retentionops_executor LOGIN PASSWORD :'executor_password';
GRANT CONNECT ON DATABASE production TO retentionops_executor;
GRANT USAGE ON SCHEMA application TO retentionops_executor;
GRANT SELECT, DELETE ON application.audit_logs TO retentionops_executor;
```

Grant nothing wider. The connector cannot escalate past what you grant, and the grants are the
control that still holds if everything in this repository is wrong.

Do **not** grant `TRUNCATE`, `UPDATE`, DDL, or membership in a role that has them. The connector
never issues any of those, so granting them adds risk and buys nothing.

## TLS

`verify-full` is the default and should stay that way outside a laptop.

| Mode | Encrypted | Server proves it is the CA's | Hostname checked |
|---|---|---|---|
| `require` | yes | no | no |
| `verify-ca` | yes | yes | no |
| `verify-full` | yes | yes | yes |

`require` protects against passive interception and nothing else — anything that can answer on
port 5432 is accepted. The connection test refuses to report success if the session turned out to
be unencrypted while the configuration asked for more, and it checks `pg_stat_ssl` for *this
connection* rather than the server's global `ssl` setting.

## What the statements do

Every statement the connector can emit is in [`../adapters/postgres/sql.go`](../adapters/postgres/sql.go).

**Count.** One read-only transaction, statement timeout applied:

```sql
SELECT count(*)::bigint, min("created_at"), max("created_at")
  FROM "application"."audit_logs"
 WHERE "created_at" < $1;
```

**Size.** An estimate from the planner's own statistics — `pg_total_relation_size` scaled by the
candidate share of `reltuples`. Deliberately not a sum over the rows: an exact figure would mean
scanning every candidate row's contents, which is the one thing this connector exists never to do.

**Delete.** One transaction per batch, never one for the job:

```sql
WITH doomed AS (
    SELECT ctid FROM "application"."audit_logs"
     WHERE "created_at" < $1
     ORDER BY "created_at"
     LIMIT $2
)
DELETE FROM "application"."audit_logs"
 WHERE ctid IN (SELECT ctid FROM doomed)
   AND "created_at" < $1;
```

- `ctid` rather than a primary key, because a retention target is not guaranteed to have one and
  this keeps the statement identical for every table.
- The retention predicate and hold exclusions are repeated on the outer `DELETE`, so a row that
  changes while the connector waits for its lock is rechecked before deletion.
- PostgreSQL requires `UPDATE` privilege for every row-lock mode that supports `SKIP LOCKED`.
  The executor is deliberately never granted that privilege; the local `lock_timeout` bounds any
  wait instead.
- The final batch is trimmed so the job cannot exceed the approved ceiling by up to one batch.
  Ceilings that are approximately respected are not ceilings.

**Discover.** `information_schema`, filtered to your allow-listed schemas in the database rather
than in Go, so nothing you did not allow-list crosses the wire.

## Timeouts

Set on every transaction, from the effective limits — the smaller of what the control plane asked
for and what your local policy permits:

```sql
SET LOCAL statement_timeout = 30000;
SET LOCAL idle_in_transaction_session_timeout = 30000;
SET LOCAL lock_timeout = 5000;
```

`idle_in_transaction_session_timeout` protects you from us: a connector that stalls mid-batch must
not hold locks indefinitely on a production table.

## Operational notes

**Autovacuum.** A large retention run creates a large number of dead tuples. Deleting a year of
history in one job will make autovacuum work; batching spreads it out but does not remove it. On
a very large table, consider several smaller retention windows rather than one big first run.

**Indexes.** The predicate column should be indexed. Without it, every batch is a sequential scan
and the statement timeout will fire long before the job finishes — which is a safe failure, but a
slow way to discover a missing index.

**Partitioned tables.** The connector deletes rows; it does not drop partitions. If your retention
boundary aligns with a partition boundary, dropping the partition is faster and cheaper, and the
connector is the wrong tool for it.

**Replicas.** Point the source at the primary. A delete on a replica is not a thing, and a count
taken on a lagging replica would make every drift check unreliable.

**Connection count.** The connector runs one job at a time and opens at most two connections per
job — one reader, one executor, both closed when the job ends.

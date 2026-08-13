# Connector protocol v1

Everything needed to reimplement either side. The JSON Schemas in [`../protocol/v1/`](../protocol/v1/)
are normative; this document explains them.

## Transport

HTTPS, TLS 1.2 or better, always initiated by the connector. No inbound port.

| Method | Path | Signed | Purpose |
|---|---|---|---|
| `POST` | `/connector/v1/enroll` | no | Exchange a single-use token for an identity |
| `GET` | `/connector/v1/jobs/next?wait=N` | yes | Long poll; `204` when idle |
| `POST` | `/connector/v1/jobs/{id}/ack` | yes | Job received and verified |
| `POST` | `/connector/v1/jobs/{id}/events` | yes | One progress record |
| `GET` | `/connector/v1/jobs/{id}/control?request_nonce=N` | yes | Signed next-batch decision |
| `POST` | `/connector/v1/jobs/{id}/complete` | yes | The signed result |
| `POST` | `/connector/v1/heartbeat` | yes | Liveness and self-declared shape |

Long polling rather than a persistent connection: it survives NAT, forward proxies and corporate
middleboxes that would drop an idle socket or refuse a WebSocket upgrade, and it needs no
reconnection state machine.

## Canonical JSON

Signatures and digests are taken over RFC 8785 canonical JSON, restricted to this protocol's value
space: objects, arrays, strings, booleans, null, and **integers only**.

Floating-point numbers are refused rather than serialized. RFC 8785 does define a canonical form
for doubles, but making a Go and a Python implementation agree bit-for-bit on every one of them is
a far larger commitment than a retention protocol needs — and a digest that disagrees across
implementations is a signature that fails in production, not in a test. Every numeric member in
every schema here is therefore an integer.

Object members are ordered by UTF-16 code unit. Every member name in this protocol is ASCII, where
that coincides with byte order; the implementations do it properly anyway so that stays a property
of the data rather than an assumption in the code.

## Signatures

Ed25519 throughout. Encoding is `ed25519:` followed by standard base64 of the 64 signature bytes.

Each signature covers a domain label, a newline, then the bytes being attested. The label keeps a
job signature from ever being accepted as an evidence signature.

| What | Domain | Signed bytes |
|---|---|---|
| Job envelope | `RetentionOps-Job-v1` | canonical(envelope minus `signature`) |
| Job result | `RetentionOps-Evidence-v1` | the `result_digest` string |
| Execution control | `RetentionOps-Control-v1` | canonical(control minus `signature`) |
| HTTP request | `RetentionOps-Request-v1` | `method\npath\ntimestamp\nnonce\nsha256:<hex of body>` |

`path` in a request signature is the **request target**: path *and* query string, exactly as sent.
The body digest of an empty body is the digest of zero bytes.

A verifier must check the signature against **the bytes it received**, not against a re-encoding of
a parsed document. Re-serializing and hoping it reproduces the signer's bytes is how signature
verification quietly stops meaning anything.

### Request headers

```
X-RetentionOps-Protocol:     1
X-RetentionOps-Connector:    <connector uuid>
X-RetentionOps-Organization: <organization uuid>
X-RetentionOps-Timestamp:    <RFC 3339>
X-RetentionOps-Nonce:        <22 url-safe base64 chars>
X-RetentionOps-Signature:    ed25519:<base64>
```

The control plane binds its database session to the claimed organization and looks the connector
up inside it, so a false claim finds no row and is refused exactly like an unknown connector.

## Operations

The set is closed. Adding a member is a protocol version change and a security review, because
each one is a new privilege granted to a remote party over a customer's database.

| Operation | Identity used | Needs target | Needs approval |
|---|---|---|---|
| `POSTGRES_TEST_CONNECTION` | reader (+ executor if any table grants delete) | no | no |
| `POSTGRES_DISCOVER` | reader | no | no |
| `POSTGRES_COUNT` | reader | yes | no |
| `POSTGRES_DELETE` | reader, then executor | yes | yes, plus drift policy |

There is no `execute_sql`, no `execute_script`, no `shell`, no `exec`, and no field in any schema
that could carry one. That is the containment boundary, and it is why the operation list is short
enough to print.

`POSTGRES_COUNT` and `POSTGRES_DELETE` carry the same frozen declarative scope: target, time
predicate, optional eligibility `condition`, and one or more legal-hold conditions in `holds`.
Conditions are a closed tree (`all`, `any`, `not`, or one column/operator/value leaf), not a
general expression language. Every value is bound as a PostgreSQL parameter; only simple
validated identifiers reach the SQL compiler. Hold matches are always excluded locally, for both
the count a person approves and the later delete recount.

## Verification order

A conforming connector performs these in order and stops at the first failure:

1. strict decode — unknown members are a refusal, not something to ignore;
2. structural validation — enums, identifier patterns, numeric ranges, required members;
3. `organization_id` matches the enrolled identity;
4. `connector_id` matches the enrolled identity;
5. not expired, and `issued_at` not more than two minutes in the future;
6. signature verifies against the **pinned** control-plane key;
7. nonce unused — and only now consumed;
8. data source is configured locally;
9. local safety policy authorizes it.

The signature is checked before the nonce is consumed, so an unsigned flood cannot fill a
connector's replay ledger with entries that would then refuse the control plane's real jobs.

## What discovery reports

`POSTGRES_DISCOVER` returns structure: for each table in an allow-listed schema, its name, a row
estimate, and for each column a name, a type, nullability, primary-key membership, and — when the
database declares one — the schema, table and column a foreign key points at.

Two properties of that last member are worth stating, because they are enforced rather than
promised:

- **Both ends stay inside `allowed_schemas`.** A key whose target lives in a schema you did not
  allow-list is dropped, not reported. Naming that table would disclose that it exists, which is
  the disclosure allow-listing a schema exists to prevent.
- **Nothing is inferred.** A column called `customer_id` with no declared constraint produces no
  relationship. The connector reports what `pg_constraint` holds and never what a name suggests.

The constraint's own name is not reported. A composite key is reported as one reference per
column pair, paired as the database stores them.

There is still no member anywhere in the result able to hold a row, a column value, a key or a
credential. See [`result.schema.json`](../protocol/v1/result.schema.json).

## Refusal and failure codes

Stable, never translated. A refusal is a `DENIED` result carrying a `denial_code`; an operational
problem is a `FAILED` result carrying a `failure_code`. Both are signed by the connector.

A driver message is never forwarded — a PostgreSQL error can quote a row value. The class travels;
the detail stays in the customer's own logs.

See the enums in [`result.schema.json`](../protocol/v1/result.schema.json).

## Drift

A destructive job must carry a `drift` block with the row count its plan measured and a tolerance.
The connector recounts immediately before deleting and returns `PLAN_STALE` if the absolute
difference has moved further in either direction than both limits allow. `max_basis_points` is
fixed-point: `50` means 0.5%. No floating-point number enters the signed document.

The customer-owned local policy is the maximum authority. Its production default requires an
exact match below 1,000 planned rows, then allows at most the tighter of 50 basis points and 100
rows. The control plane may request a stricter tolerance; a missing or wider tolerance is refused
before the executor credential is resolved.

The control plane also verifies that a signed result names the same data source, operation, plan
digest and approval as the stored job. A valid connector signature cannot be moved from a count
to a delete, or from one approved instruction to another.

## Checkpoint control

The approved `JobEnvelope` is immutable. Pause and cancellation are carried by a distinct
`ExecutionControl` whose only possible actions are `RUN`, `PAUSE`, and `CANCEL`. The connector
requests one before the first destructive batch and after every committed batch.

Each answer names the job, organization, connector and monotonic execution version, expires after
30 seconds, and echoes the fresh `request_nonce` challenge in that request. This prevents a
captured earlier `RUN` answer from authorizing a later checkpoint. The signature is verified
against the control-plane key pinned at enrollment and under its own signing domain.

Only `RUN` authorizes the next batch. A missing, expired, malformed, stale-version or unverifiable
answer fails closed: the connector waits locally, holding no transaction or row lock, and retries.
`PAUSE` is reported idempotently until acknowledged; a later fresh `RUN` resumes the same immutable
job. `CANCEL` produces a signed `CANCELLED` result whose statistics cover batches already committed.

## Versioning

`protocol_version` is `"1"` and is checked exactly. A connector refuses anything else rather than
guessing; forward compatibility is obtained by shipping a new connector, not by tolerating unknown
input. Unknown members are refused for the same reason: a control plane that grew a field this
connector does not understand must not be silently obeyed in part.

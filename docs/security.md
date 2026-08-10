# Security model

This document states what the connector guarantees, what it does not, and where each guarantee
lives in the code so you can check it rather than believe it.

## Threat assumption

**The control plane may be compromised.**

Not "is unlikely to be" — may be. Every design decision below follows from taking that seriously,
because a connector whose safety depends on the control plane being honest provides no security
property at all; it is just a remote shell with extra steps.

## The two boundaries

**Boundary 1 — cryptographic.** Did RetentionOps really ask for this?
Ed25519 signature over the canonical form of the received bytes, verified against a key pinned at
enrollment. Answers authenticity. Does *not* answer whether the request is acceptable.

**Boundary 2 — local policy.** Should RetentionOps be able to ask for this at all?
A file on your host, which no protocol message reads or writes. Answers authorization.

An attacker who steals the control plane's signing key defeats boundary 1 completely and gains:
the ability to run one of four operations, on tables you allow-listed, within limits you set,
with a human approval they must also have forged, up to a row ceiling you chose — and to leave a
signed record of every attempt on your host.

## Key handling

| Key | Generated | Stored | Ever transmitted |
|---|---|---|---|
| Connector private key | On your host, during `enroll`, before the first network call | `identity.json`, mode `0600`, in a directory the connector refuses to use unless it is `0700` | Never. There is no protocol field that could carry it. |
| Connector public key | Same moment | Same file | Once, in the enrollment request |
| Control-plane public key | By us | Same file, pinned | Received once, at enrollment |

The control-plane key is **pinned and never refreshed from the network**. A rotation requires
re-enrollment, which is a deliberate, customer-initiated action. This is the difference between
"an attacker who can answer one HTTPS request can become the party you obey" and "they cannot".

## Replay

Every job carries a single-use nonce, an expiry, its target connector id and its organization id.
The nonce ledger is a directory of files created with `O_EXCL` — an atomic first-use test that
stays correct even if two connector processes are started against the same state directory, which
an in-memory set would get silently wrong.

A connector that crashes between consuming a nonce and running the job loses that job. The
control plane times it out and issues a fresh one. For a destructive operation this is the
correct trade: the failure mode is "did not run", never "ran twice".

## Request authentication to the control plane

There is no bearer token. Each HTTP call is signed individually, over method, path, timestamp,
nonce and body digest. Nothing replayable is in flight, so a proxy log, a memory dump or a
mis-scoped observability pipeline yields no credential.

## Pause and cancellation

The connector checks a separately signed control document before the first destructive batch and
after every committed batch. The answer is short-lived and bound to a fresh connector-generated
challenge, so an old `RUN` cannot be replayed after an operator asks for `PAUSE` or `CANCEL`.

Control loss fails closed. An unreachable or revoked control plane, an expired answer, a bad
signature, or a version regression starts no further batch. The connector may keep an idle
database connection while paused, but it holds no open transaction and no row lock. A batch that
already committed remains committed and is included in the eventual signed result.

## What never leaves your network

- Row values. No operation reads one; no schema member could carry one.
- Database credentials. Resolved locally; no protocol field exists for them.
- Database error messages. A PostgreSQL error can quote a row value, which is exactly why the
  connector sends a stable failure class and keeps the detail in your own logs.
- Hostnames, IP addresses and connection strings. The control plane knows a data source's UUID
  and its display name — both of which you chose.
- Your table names, except for those in schemas you allow-listed, and only in response to an
  explicit discovery job.

## What we do learn

Enough to operate the service: which connectors are online, which policy digest they are running,
how many tables each source allows, aggregate counts and byte estimates from plans, and the
outcome codes of jobs. See [architecture.md](architecture.md#what-the-control-plane-learns).

## Local logs

The connector logs to stderr in JSON. It writes hostnames, database names and table names, all of
which are yours and already known to you. It does not write credentials or row content: there is
no code path that puts one into a log call, and a redaction filter in `internal/telemetry` destroys
the value of any attribute whose key resembles a secret — a second control for the code that has
not been written yet.

## What this design does not protect against

Stated plainly, because a security document that only lists strengths is marketing.

- **Root on the connector host.** An attacker there has your database credentials directly. The
  connector is not the boundary being tested at that point.
- **Write access to the configuration file.** The local safety policy is the control; someone who
  can edit it can widen it. Protect it as you would protect a database grant.
- **A malicious approval inside your own organization.** RetentionOps enforces separation of
  duties, but a sufficiently privileged insider approving a bad plan is an organizational control,
  not a technical one.
- **Retention policy that is simply wrong.** The connector will faithfully delete what a correct,
  approved plan describes. `max_delete_rows` is your circuit breaker; set it to a number you could
  live with losing.
- **Availability of your database.** Batching, short transactions and local timeouts keep a
  retention job from competing with production traffic, but a very large delete still produces WAL
  and still triggers autovacuum.

## Reporting

See [SECURITY.md](../SECURITY.md).

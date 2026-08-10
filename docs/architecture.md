# Architecture

## The split

RetentionOps is two programs with one boundary between them.

| | Control plane | Connector |
|---|---|---|
| Where it runs | Solutions Optigm infrastructure | Your network |
| Licence | Proprietary | Apache-2.0 (this repository) |
| Holds | policies, plans, approvals, evidence, tenancy, billing | database credentials |
| Can reach your database | no | yes |
| Decides *what should* happen | yes | no |
| Decides *what may* happen | no | yes |

The last two rows are the whole design. The control plane is the authority on intent: which
policy applies, what the plan says, who approved it. The connector is the authority on
permission: whether this operation, on this table, with these limits, is something the customer
ever agreed to. Neither can do the other's job, and neither can override the other.

## Why the connector is the open-source half

An agent that runs inside a customer's network and can delete their production data is the single
hardest thing to get past a security review — and the reviewer is right to be difficult. The
useful answer is not a certification or a policy document. It is: here is the source, here is the
list of every statement it can emit, here is the file where you decide what it can touch, and
here is the test that proves it refuses everything else.

Making the planner or the billing system open source would not help that reviewer at all. They
never run on the customer's network.

## Request flow

```
control plane                     connector                         database
     │
     │  (connector polls; nothing is pushed)
     │◄──── GET /jobs/next?wait=30 ─────┤
     │                                  │
     ├───── signed JobEnvelope ────────►│
     │                                  ├── 1. decode strictly, refuse unknown fields
     │                                  ├── 2. is it addressed to me, in my organization?
     │                                  ├── 3. is it still valid, not from the future?
     │                                  ├── 4. does the signature verify against the PINNED key?
     │                                  ├── 5. is the nonce unused?  (consume it)
     │◄──── POST /jobs/{id}/ack ────────┤
     │                                  ├── 6. do I even have this data source configured?
     │                                  ├── 7. LOCAL POLICY: table, column, verb, ceilings, approval
     │                                  │
     │                                  ├── 8. resolve the reader secret ──► secret manager
     │                                  ├── 9. recount ───────────────────────────────► SELECT
     │                                  ├── 10. drift within tolerance? else PLAN_STALE
     │                                  ├── 11. resolve the EXECUTOR secret ► secret manager
     │◄──── GET /jobs/{id}/control ─────┤ 12. signed RUN / PAUSE / CANCEL checkpoint
     │◄──── POST /jobs/{id}/events ─────┤ 13. DELETE, one committed batch at a time ──► DELETE
     │      (one per batch)             │
     │◄──── GET /jobs/{id}/control ─────┤     checkpoint after every commit
     │◄──── POST /jobs/{id}/complete ───┤ 14. sign the result with the connector's own key
     │      signed JobResult            │
```

Steps 1–7 all happen before a single byte reaches the database. Step 11 is the first moment the
destructive credential exists in this process's memory, and it is reached only after a human
approval has been verified locally.

The checkpoint decision never changes the job. Only a fresh signed `RUN` allows the next batch;
`PAUSE`, `CANCEL`, revocation, expiry, a subscription state that no longer permits writes, loss of
connectivity, or an invalid answer stops locally after the last committed transaction. A paused
job resumes in place so its final signed result still covers the entire operation.

## Packages

| Path | Responsibility |
|---|---|
| `protocol/v1/` | The wire contract: types, JSON Schemas, canonical JSON, signing domains. The only package a third party must read to know everything the control plane can ask for. |
| `internal/policy/` | The local safety policy. Pure functions of (policy, job, clock). |
| `internal/jobs/` | Verification pipeline and the durable replay ledger. |
| `internal/identity/` | Ed25519 key pair, the pinned control-plane key, signing. |
| `internal/enrollment/` | The one-time exchange that creates an identity. |
| `internal/controlplane/` | The outbound HTTP client. Per-request signatures, long polling. |
| `internal/agent/` | The run loop. One job at a time. |
| `internal/evidence/` | Building and sealing signed results, including refusals. |
| `internal/config/` | Loading and validating the customer's file. |
| `internal/telemetry/` | Local logs and Prometheus metrics. Nothing is shipped to us. |
| `internal/doctor/` | Diagnostics, over the same code paths the connector uses. |
| `adapters/postgres/` | The only code that touches a customer database. |
| `secrets/` | Credential resolution. `env`, `file`, `aws-secrets-manager`. |

`internal/` is used literally: nothing under it is importable by another module, so the module's
public surface is `protocol/v1` and `secrets` — the contract and the extension point.

## Two identities, resolved at different times

A source configures a `reader` and an `executor`. This is not just least privilege in the
database; it is least privilege *in this process*.

The executor's secret is resolved in exactly one place, on exactly one path: the destructive
branch, after verification, after the local policy, after the approval check, after the drift
recount. On any other path the destructive credential is never fetched, so a flaw in planning —
or in the discovery code, or in the count path — cannot yield it. It was never in memory.

## What the control plane learns

Counts. Byte estimates. Boundary timestamps. Column names and types, for schemas you allow-listed.
A server version. A TLS mode. Stable status and refusal codes. Two digests.

That is the complete list, and it is enforced structurally: the result schema declares
`additionalProperties: false`, the Go struct has no member that could hold a value, and the
connector has no operation that reads one.

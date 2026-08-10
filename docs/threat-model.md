# Threat model

Written from the assumption that the control plane can be compromised. Each row names the abuse,
the control, and where to check it.

## Attacks from a compromised or malicious control plane

| Abuse | Control | Where |
|---|---|---|
| Send SQL to run | The protocol has no field that can carry SQL. Four declarative operations. | `protocol/v1/job.schema.json` |
| Name a table the customer never approved | Local allow-list, refused with `DENIED_TARGET_NOT_ALLOWED` | `internal/policy/policy.go` |
| Delete on a table granted only `inspect` | Verb check per table | `policy_test.go` |
| Predicate on an arbitrary column | Column must be in `retention_columns` | `DENIED_COLUMN_NOT_ALLOWED` |
| Ask for ten million rows | `max_delete_rows`; refused, never clamped | `DENIED_ROW_LIMIT_EXCEEDED` |
| Ask for one giant batch to hold locks | `max_batch_size` | `DENIED_BATCH_LIMIT_EXCEEDED` |
| Delete without a human approval | Approval required and checked locally, independently | `DENIED_APPROVAL_REQUIRED` |
| Reuse an expired approval | Approval expiry checked against the local clock | `DENIED_APPROVAL_EXPIRED` |
| Raise the local limits remotely | There is no protocol message that writes local policy. The absence *is* the control. | whole protocol |
| Point a job at another customer's connector | `connector_id` and `organization_id` must match the enrolled identity | `internal/jobs/verifier.go` |
| Exfiltrate rows through the result | Result schema has no member that can hold a value; `additionalProperties: false` | `protocol/v1/result.schema.json` |
| Exfiltrate rows through an error message | Driver messages never forwarded; stable failure classes only | `adapters/postgres/adapter.go` |
| Ask for the connector's private key | No protocol field exists; it never leaves `identity.json` | `internal/identity/` |

## Attacks from the network

| Abuse | Control |
|---|---|
| Forge a job | Ed25519 signature over the received bytes, verified against a key pinned at enrollment |
| Replace the pinned key by answering one request | The key is never refreshed from the network; rotation requires re-enrollment |
| Replay a captured `DELETE` | Single-use nonce in a durable `O_EXCL` ledger, plus expiry, plus connector binding |
| Replay a captured API call to the control plane | Per-request signature over method, path, timestamp, nonce and body digest |
| Steal a bearer token in transit | There is no bearer token |
| Strip TLS between connector and control plane | `control_plane.url` must be `https`; plaintext is refused at config load, not warned about |
| Impersonate the customer's database | `tls.mode: verify-full` by default; the connection test refuses to report success on an unencrypted session |
| Exhaust connector memory with a huge response | Response bodies are read through a 1 MiB limit reader |
| Flood the replay ledger to cause self-denial | The signature is verified *before* the nonce is consumed |

## Attacks on the enrollment exchange

| Abuse | Control |
|---|---|
| Steal an enrollment token | Single use, short lived, stored only as a digest, burned in the transaction that records the identity |
| Enrol a connector into another organization | The token is scoped to one organization and looked up inside a session bound to it |
| Man-in-the-middle the first exchange | TLS; and the operator compares the printed key fingerprint against the console before starting the connector |

## Attacks on the host

| Abuse | Control |
|---|---|
| Read the private key as another local user | `identity.json` is `0600`; the connector refuses to start if the directory is group- or world-readable |
| Read a credential file | The `file` provider refuses a file readable by group or other |
| Read a credential from the process environment | The `env` provider exists but is documented as the weakest option; `file` and `aws-secrets-manager` are preferred |
| Turn an SSRF into an AWS credential leak | IMDSv2 only; IMDSv1 is never attempted |
| Read a credential from a crash dump | The password is never part of a connection string; it is set on the parsed config after the DSN is built |
| Find a credential in a log | No code path logs one; a redaction filter destroys any attribute whose key resembles a secret |

## Attacks on the customer's database

| Abuse | Control |
|---|---|
| Long-running delete blocks production writes | One transaction per batch and a locally bounded `lock_timeout` |
| A stalled connector holds locks forever | `idle_in_transaction_session_timeout` on every transaction |
| A runaway query pins a connection | `statement_timeout` on every transaction |
| Delete rows added since the plan was approved | Recount before executing, refused as `PLAN_STALE` beyond the declared tolerance |
| Exceed the approved row count by a partial batch | The final batch is trimmed to the remaining allowance |
| Delete via the planning path | The planning transaction is opened `READ ONLY`, and the executor secret is never resolved on it |

## Residual risks

- **Root on the connector host** yields the database credentials directly. The connector is not
  the boundary at that point.
- **Write access to the configuration file** is write access to the safety policy. Protect it as
  you would a database grant.
- **A wrong-but-approved retention policy** will be executed faithfully. `max_delete_rows` is the
  circuit breaker; choose it as a number you could live with losing.
- **A malicious insider with approval rights.** Separation of duties is enforced in the control
  plane, but this is ultimately an organizational control.
- **Supply chain.** Verify release signatures and pin image digests; see [releases.md](releases.md).
  A connector you did not verify is a connector you have to trust, which is the situation this
  whole design exists to avoid.

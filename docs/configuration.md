# Configuration reference

One YAML file, by default `/etc/retentionops/connector.yaml`.

Unknown fields are a **startup error**, not a warning. A typo in a limit would otherwise be
silently ignored and leave you believing a control is in force that is not, which is worse than
having no control at all.

## `control_plane`

| Field | Default | Notes |
|---|---|---|
| `url` | — | Required. Must be `https`. Plaintext is refused at load, not warned about. |
| `poll_wait_seconds` | `30` | How long the control plane may hold a poll open. 1–300. |
| `heartbeat_seconds` | `30` | 5–3600. |
| `ca_file` | — | A privately signed control plane, or a TLS-inspecting egress proxy. Absent means the system trust store, which is correct for a publicly trusted control plane. |

`init` asks for the certificate and records where to copy it from; `install` places it at
`/etc/retentionops/certs/control-plane-ca.pem` and the generated `compose.yaml` mounts it. The
bundle therefore carries its own trust: installing the certificate into the host trust store
instead would work, but leaves the connector depending on machine state that nothing in the
bundle records and no later command can verify or reproduce on the next host.

## `identity` and `state`

| Field | Notes |
|---|---|
| `identity.directory` | Where `identity.json` lives. Must be mode `0700`; the connector refuses to start otherwise. |
| `state.directory` | Where the replay ledger lives. |

## `telemetry`

| Field | Default | Notes |
|---|---|---|
| `metrics_address` | *(disabled)* | e.g. `127.0.0.1:9102`. Empty opens no socket at all. |
| `log_format` | `json` | `json` or `text`. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |

Nothing here is shipped to RetentionOps.

## `sources.<data-source-uuid>`

The key is the data source UUID the console issued when you created the source. Copy it exactly.

| Field | Default | Notes |
|---|---|---|
| `type` | — | `postgresql` is the only implemented type. |
| `mode` | inferred for legacy files | `discovery_only` or `execution`. `discovery_only` refuses every delete before resolving an executor secret. |
| `host`, `database` | — | Required. |
| `port` | `5432` | |
| `tls.mode` | `verify-full` | `verify-full`, `verify-ca` or `require`. |
| `tls.ca_file` | — | Required unless mode is `require`. |
| `reader` | — | Required. |
| `executor` | — | Required only if some table grants `delete`. |
| `safety` | — | Required. See below. |

### Credentials

```yaml
reader:
  username: retentionops_reader
  password: { provider: aws-secrets-manager, ref: prod/retentionops/reader#password }
```

`username` must be a plain lowercase identifier. The reader and the executor must not be the same
role — that would erase the separation the two-identity design exists for, and the connector
refuses it.

| Provider | `ref` is | Notes |
|---|---|---|
| `file` | A path | Preferred. Refuses a file readable by group or other. A trailing newline is trimmed. |
| `aws-secrets-manager` | A name or ARN, optionally `#member` to select one key of a JSON secret | Credentials from environment, ECS/EKS task role, or IMDSv2. Web identity (IRSA) is not implemented — use `file` with a projected secret. |
| `env` | A variable name | Weakest option: environment variables are visible in process listings, `docker inspect` and crash dumps. |

## `sources.<id>.safety`

**This block is yours.** No RetentionOps message reads it, and none can change it. Its digest
travels in the heartbeat so the console can show which policy was in force — a change there is
always the visible consequence of someone editing this file on your host.

| Field | Notes |
|---|---|
| `allowed_schemas` | Required, non-empty. Also bounds what discovery reports — including both ends of a foreign key, so a relationship leaving this list is dropped rather than reported. |
| `require_approval` | `true` refuses any destructive job without a valid human approval, independently of what the control plane believes. |
| `drift` | Customer-owned maximum recount tolerance. Defaults to the conservative bounded policy below. |
| `max_delete_rows` | Source-wide row ceiling. |
| `max_batch_size` | Source-wide batch ceiling. |
| `statement_timeout_seconds` | Upper bound; a job asking for more is **lowered** to this. |
| `lock_timeout_seconds` | Same. |
| `max_duration_seconds` | Same. |
| `tables` | The allow-list. Anything not here is unreachable. |

### `drift`

```yaml
drift:
  mode: bounded
  exact_match_below_rows: 1000
  max_basis_points: 50  # 0.5%
  max_rows: 100
```

`bounded` requires an exact recount below 1,000 planned rows. At or above that threshold, both
limits apply, so the permitted difference is the smaller of 0.5% and 100 rows. Use
`drift: {mode: strict}` to require equality for every destructive plan. A signed job may request
less tolerance; one requesting more is refused. Omitting the block selects the bounded production
default, not an unlimited mode.

### `tables[]`

| Field | Notes |
|---|---|
| `schema`, `table` | Plain lowercase identifiers, and `schema` must be in `allowed_schemas`. |
| `actions` | `inspect`, `delete`, or both. An entry granting nothing is a startup error — remove it instead. |
| `retention_columns` | The only columns a predicate may reference. Required if `delete` is granted. |
| `max_delete_rows` | Table ceiling. The tighter of table and source applies. |
| `max_batch_size` | Table ceiling. |

### Refused, not clamped

A job asking for **more scope** than you granted — more rows, a bigger batch — is **refused**.

Clamping would be friendlier and wrong. The plan a human approved said "up to 60 000 rows";
quietly doing 50 000 executes an operation nobody approved and reports success for it. You see the
refusal and either raise the ceiling deliberately or re-plan.

**Protective timeouts** are the exception: they are lowered rather than refused, because a shorter
statement timeout can only make a job give up earlier. It bounds damage; it does not change scope.

## Startup refusals

The connector will not start with a policy it would have to interpret:

- `allowed_schemas` empty — a source with no reachable schema is a misconfiguration, not a lockdown;
- a table naming a schema absent from `allowed_schemas`;
- `delete` granted with no `retention_columns` — a delete with no bounded predicate is a table drop
  in slow motion;
- `delete` granted with no row ceiling at either level;
- the same table declared twice — which entry applies would be ambiguous;
- any identifier that is not a plain lowercase identifier;
- an unknown action;
- an unknown drift mode, incomplete bounded drift policy, or tolerance outside its range;
- reader and executor sharing a username.

Check yours before deploying:

```bash
retentionops-connector validate-config --config /etc/retentionops/connector.yaml
```

New `init` bundles always start with `mode: discovery_only`, no executor credential and no table
granting `delete`. To enable execution, generate a separate local review bundle:

```bash
retentionops-connector execution enable \
  --config /etc/retentionops/connector.yaml \
  --source 4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52 \
  --table application.audit_logs:created_at
```

Review its `roles.sql`, apply that SQL as the DBA, then run `execution apply
--database-role-applied`. The executor password is masked by default; unattended operation may
use `--executor-secret-file`. The live local policy is backed up and changed only at that final
explicit step.

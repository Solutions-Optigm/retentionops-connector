# Installation and operation guide

This guide takes a PostgreSQL connector from a reviewed release to a supervised service in your
network. It is written for the person who administers the host and the database, not for the
RetentionOps control-plane operator.

The connector is deliberately a small, customer-controlled data plane. It makes outbound HTTPS
connections to RetentionOps, resolves credentials locally, and can use only the operations in the
v1 protocol. It never accepts an inbound RetentionOps connection, a SQL statement, a shell
command, or a remote edit to this configuration file.

> **Current product status:** enrollment, diagnostics, connection tests, schema discovery and the
> signed connector gateway are available. The hosted console workflow that connects policy
> planning, approval and destructive execution through the gateway is still being delivered.
> Do not treat this document as confirmation that a hosted deletion workflow is available in your
> account. The local safeguards described below apply to every version.

## 1. Before you begin

You need:

- a Linux host that can reach your PostgreSQL primary and `connector.retentionops.app` over HTTPS;
- an organisation UUID and a single-use enrollment token issued by your RetentionOps organisation
  administrator;
- a data-source UUID issued by the control plane;
- a PostgreSQL CA certificate and two distinct database roles;
- a persistent local directory for the connector identity and replay ledger; and
- either credential files or a supported secret provider (`file`, `aws-secrets-manager`, or `env`).

Use a dedicated non-root service account. Keep the connector close to the database network, but
give it only the egress it needs:

| From the connector | Destination | Port | Required for |
|---|---|---:|---|
| Connector host | `connector.retentionops.app` | 443/tcp | Enrollment, polling, heartbeats and evidence |
| Connector host | PostgreSQL primary | 5432/tcp | Source checks and retention operations |
| Connector host | Secret manager | 443/tcp | Only when using AWS Secrets Manager |

No inbound firewall rule is required. If Prometheus metrics are enabled, bind them to loopback or
to a private monitoring network; they are the only optional listener.

Keep the system clock synchronised with NTP. Jobs and request signatures are time-bound; a clock
that is more than a few minutes wrong will cause safe refusals such as `DENIED_JOB_EXPIRED`.

## 2. Prepare PostgreSQL

Create separate roles for reading and deleting. The reader is used for checks, discovery and
counting. The executor is resolved only on the destructive path, after signature, local-policy and
approval checks have passed.

Adapt the database, schema and table names, then grant no more than this:

```sql
CREATE ROLE retentionops_reader LOGIN PASSWORD :'reader_password';
GRANT CONNECT ON DATABASE production TO retentionops_reader;
GRANT USAGE ON SCHEMA application TO retentionops_reader;
GRANT SELECT ON application.audit_logs TO retentionops_reader;

CREATE ROLE retentionops_executor LOGIN PASSWORD :'executor_password';
GRANT CONNECT ON DATABASE production TO retentionops_executor;
GRANT USAGE ON SCHEMA application TO retentionops_executor;
GRANT SELECT, DELETE ON application.audit_logs TO retentionops_executor;
```

Do not grant `TRUNCATE`, `UPDATE`, DDL rights, role membership, or broad schema/table privileges.
Database grants remain an independent containment boundary: the connector cannot escalate them.

The target should be the primary, not a replica. Index every retention predicate column (for
example `application.audit_logs(created_at)`) before using a large table. The connector deletes in
batches with a locally bounded lock timeout; it does not drop partitions. Partition dropping is a
separate database operation and is intentionally outside this protocol.

Use PostgreSQL TLS `verify-full` with the CA that issued the database server certificate. This is
the default; `require` encrypts the connection but does not authenticate the server.

## 3. Install a verified package

### Official release

Releases are published at
<https://github.com/Solutions-Optigm/retentionops-connector/releases>. Download the binary for your
architecture together with the checksum manifest and its Sigstore material:

```bash
arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
base=https://github.com/Solutions-Optigm/retentionops-connector/releases/latest/download
curl -fsSLO $base/retentionops-connector-linux-$arch
curl -fsSLO $base/retentionops-connector-linux-$arch.sig
curl -fsSLO $base/retentionops-connector-linux-$arch.pem
curl -fsSLO $base/checksums.txt
```

Before installing an official binary or image, verify its checksum and Sigstore signature as
described in [releases.md](releases.md). For an image, verify it first and deploy its immutable
digest rather than a movable tag.

```bash
sha256sum -c checksums.txt --ignore-missing

cosign verify-blob \
  --certificate retentionops-connector-linux-amd64.pem \
  --signature retentionops-connector-linux-amd64.sig \
  --certificate-identity-regexp 'https://github\.com/Solutions-Optigm/retentionops-connector/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  retentionops-connector-linux-amd64
```

On Debian 13, download and verify `retentionops-connector-linux-amd64.deb` or
`retentionops-connector-linux-arm64.deb` with the same checksum and Sigstore procedure, then:

```bash
sudo apt install ./retentionops-connector-linux-amd64.deb
retentionops-connector version
```

The package creates the service account, private directories and hardened systemd unit. It never
starts or enables the service. Configuration, source checks, enrollment and a green `doctor` must
come first.

### Build from source

For an internal build, use Go 1.25.13 or later; `go.mod` refuses anything older, because earlier 1.25 patches carry known standard-library vulnerabilities this binary reaches. Building from source is supported, but it is not an
official release artifact.

```bash
git clone https://github.com/solutions-optigm/retentionops-connector.git
cd retentionops-connector
make deps
make check
make build
sudo install -o root -g root -m 0755 dist/retentionops-connector /usr/local/bin/retentionops-connector
```

## 4. Generate and review the discovery-only bundle

Run the command personalized by the console. `init` asks only for non-sensitive local metadata,
creates no empty secret file, performs no network request and executes no SQL:

```bash
sudo retentionops-connector init --platform systemd \
  --source YOUR_DATA_SOURCE_UUID \
  --organization YOUR_ORGANIZATION_UUID \
  --control-plane https://connector.retentionops.app \
  --install
```

`--install` applies the bundle in the same run, from the directory `init` chose, and asks for the
enrollment token at the end. Drop it to stop after the folder is written — nothing is installed,
nothing is sent, and you can read every generated file before applying it with the command in
section 5. Add `--repair` alongside `--install` to replace the runtime files of an earlier attempt;
each replaced file is backed up beside itself first.

`init` does not ask where the database is, which database it is, or under which role names to
connect. The console sends all four, sealed to this connector (ADR-034), and asking twice only
produced two answers to reconcile — the sealed one always won. What it does ask is local: an
output directory, the organization, an optional PostgreSQL CA source path, an optional
control-plane CA source path, where the reader password will live, and the schemas the local
safety policy permits.

Supply the control-plane CA when your control plane is self-hosted. Leaving it blank there ends
in `certificate signed by unknown authority` at enrollment, which names TLS rather than the
question whose answer fixes it — the connector now says so explicitly, but the answer is still
given here.

Leave the PostgreSQL CA blank unless your server presents a privately signed certificate this
host does not already trust; blank means the connector verifies against the host's own trust
store, which is correct for a publicly trusted certificate. A supplied certificate is copied into
the bundle and the runtime path is recorded in `bundle.json`.

Review `connector.yaml` and `bundle.json` before continuing. The generated source records
`configured_by: retentionops` and carries no address: it is declared, visible and unusable until
the console configures it. `roles.sql` is not written here — it needs the database and the role
names, and it is rendered by `source roles` once those exist.

## 5. Run the resumable assistant

```bash
sudo retentionops-connector install --bundle "$PWD/retentionops-connector-init"
```

The assistant verifies artifact digests and the CA, preserves conflicting existing files,
requests the enrollment token through masked input, enrolls, then runs `doctor`.

For a source the console configures, it stops there: there is no database to test, no roles to
confirm and no password to ask for, because nobody has named the role that password belongs to.
Those steps move after the console's configuration and are covered in section 6 below. For a
bundle that describes the database locally, it also prints an exact `psql` command for that host
and database, waits for the DBA confirmation, requests the reader password through masked input,
and tests and discovers the source before enrolling.

Its state contains completed step names only—never a password or token. After an interruption,
run the same command again.

For unattended secret input, use private files rather than arguments or environment variables:

```bash
sudo retentionops-connector install \
  --bundle "$PWD/retentionops-connector-init" \
  --reader-secret-file /secure/reader-password \
  --token-file /secure/enrollment-token
```

The initial configuration is explicitly `discovery_only`. It has no executor identity and no
table granting `delete`.

## 5b. Finish from the console

Configure the source in the RetentionOps console: host, port, database, reader role, executor
role and transport security. The console seals that document to this connector and relays a
ciphertext it cannot open; the connector applies it to its managed overlay and acknowledges.
`/etc/retentionops/connector.yaml` is never rewritten — the overlay lives beside the connector's
state and is merged at load.

Then finish on the host, where both commands can finally name what the console chose:

```bash
sudo -u retentionops retentionops-connector source roles YOUR_DATA_SOURCE_UUID \
  | psql -h YOUR_HOST -U postgres -d YOUR_DATABASE
sudo retentionops-connector secret set --role reader
```

`source roles` renders the reviewed reader-role script from the configuration in force. Read it
before applying it: it creates login roles, grants `CONNECT`, `USAGE` and `SELECT` on the schemas
your local safety policy allows, and grants no `DELETE`.

Run the connection test from the console. Its result is signed by this connector and is what
ticks the step; nothing here reports success on its own.

## 6. Enable execution separately

Only after discovery and local review, prepare an execution-enablement bundle naming every table
and retention column explicitly:

```bash
retentionops-connector execution enable \
  --config /etc/retentionops/connector.yaml \
  --source YOUR_DATA_SOURCE_UUID \
  --table public.tickets:closed_at
```

Review and apply the generated `roles.sql` as DBA. Then apply the reviewed local policy; the
executor password is requested with terminal echo disabled:

```bash
sudo retentionops-connector execution apply \
  --config /etc/retentionops/connector.yaml \
  --bundle "$PWD/retentionops-execution-enable" \
  --database-role-applied
```

Automation may additionally use `--executor-secret-file /secure/executor-password`.

The command refuses if the live policy changed after preparation and backs it up before the
atomic replacement. Nothing about this local allow-list is sent to or writable by RetentionOps.

## Legacy manual reference

The remaining sections document the individual actions the assistant performs and remain useful
for audit or recovery. New Debian installations should use the assistant above.

### Create local storage and secrets manually

Run the connector as a dedicated account. The identity directory contains the connector private
key and must be mode `0700`; the state directory contains the durable anti-replay ledger and must
survive a restart or container replacement.

```bash
sudo useradd --system --home-dir /var/lib/retentionops --shell /usr/sbin/nologin retentionops
sudo install -d -o retentionops -g retentionops -m 0700 \
  /var/lib/retentionops/identity /var/lib/retentionops/state
sudo install -d -o root -g retentionops -m 0750 /etc/retentionops /etc/retentionops/certs /etc/retentionops/secrets
```

Copy the PostgreSQL CA certificate to `/etc/retentionops/certs/postgres-ca.pem`. With the `file`
secret provider, write each password into a separate file owned by the service user and readable
by no group or other user:

```bash
sudo install -o retentionops -g retentionops -m 0400 /secure/input/reader-password \
  /etc/retentionops/secrets/reader-password
sudo install -o retentionops -g retentionops -m 0400 /secure/input/executor-password \
  /etc/retentionops/secrets/executor-password
```

`env` is supported for compatibility but is the weakest choice: environment variables can appear
in process inspection, container metadata and crash dumps. Prefer a protected file or a workload
identity with AWS Secrets Manager. Never place a literal password in the YAML configuration.

### Write the local safety policy manually

Copy [the example configuration](../examples/postgres/connector.yaml) to
`/etc/retentionops/connector.yaml`, then replace every illustrative value. This example uses local
credential files:

```yaml
control_plane:
  url: https://connector.retentionops.app
  poll_wait_seconds: 30
  heartbeat_seconds: 30

identity:
  directory: /var/lib/retentionops/identity
state:
  directory: /var/lib/retentionops/state

telemetry:
  metrics_address: 127.0.0.1:9102
  log_format: json
  log_level: info

sources:
  # Use the exact lower-case UUID issued by the RetentionOps control plane.
  4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52:
    type: postgresql
    host: db.production.internal
    port: 5432
    database: production
    tls:
      mode: verify-full
      ca_file: /etc/retentionops/certs/postgres-ca.pem
    reader:
      username: retentionops_reader
      password: { provider: file, ref: /etc/retentionops/secrets/reader-password }
    executor:
      username: retentionops_executor
      password: { provider: file, ref: /etc/retentionops/secrets/executor-password }
    safety:
      allowed_schemas: [application]
      require_approval: true
      max_delete_rows: 50000
      max_batch_size: 1000
      statement_timeout_seconds: 30
      lock_timeout_seconds: 5
      max_duration_seconds: 1800
      tables:
        - schema: application
          table: audit_logs
          actions: [inspect, delete]
          retention_columns: [created_at]
          max_delete_rows: 50000
          max_batch_size: 1000
```

The `safety` block is the customer-owned boundary. RetentionOps cannot read or modify it. Only
tables explicitly listed are reachable; only the listed retention columns can be predicates; and
the smaller source/table ceiling wins. A job that exceeds a row or batch ceiling is refused, never
quietly reduced, because reducing it would execute something other than the operation approved.

For an inspection-only source, omit `delete` from every `actions` list and omit the `executor`
section entirely. A configuration with an executor equal to the reader, unknown fields, an empty
allow-list, invalid identifiers, or an unbounded delete is rejected at startup.

Protect the file from unapproved local changes, while allowing the service account to read it:

```bash
sudo chown root:retentionops /etc/retentionops/connector.yaml
sudo chmod 0640 /etc/retentionops/connector.yaml
sudo -u retentionops retentionops-connector validate-config --config /etc/retentionops/connector.yaml
```

Record the printed policy digest in your change record. It is also reported in the connector
heartbeat so the control plane can show which local policy was in force, without receiving the
policy itself.

### Validate the source and enrol manually

Before enrollment, validate the configuration and exercise the same local code paths used in
production:

```bash
sudo -u retentionops retentionops-connector validate-config --config /etc/retentionops/connector.yaml
sudo -u retentionops retentionops-connector source test --config /etc/retentionops/connector.yaml \
  4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52
sudo -u retentionops retentionops-connector source discover --config /etc/retentionops/connector.yaml \
  4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52
```

`source test` validates TCP reachability, TLS and both configured roles. `source discover`
discovers only the locally allow-listed schemas; it never returns row content. It reports table
and column structure plus the foreign keys the database declares between allow-listed schemas —
never a relationship guessed from a column name.

Enroll once with the organisation UUID and one-time token supplied by the control plane. Treat the
token as sensitive: do not put it in tickets, terminal recordings, shell history exports or
support bundles. Enrollment creates the connector key pair locally and pins the control-plane
public key in the identity directory.

```bash
sudo -u retentionops retentionops-connector enroll \
  --config /etc/retentionops/connector.yaml \
  --url https://connector.retentionops.app \
  --organization YOUR_ORGANIZATION_UUID \
  --token-file ./enrollment-token
```

Compare the printed control-plane-key fingerprint with the fingerprint displayed by the issuing
control-plane workflow before starting the service. A mismatch is a stop condition: do not start
or re-enrol until the organisation administrator has investigated it.

Run the end-to-end diagnostic next. Fix the first `FAIL`; later failures can be consequences of
it.

```bash
sudo -u retentionops retentionops-connector doctor --config /etc/retentionops/connector.yaml
```

## 7. Activate supervision

### systemd (recommended on a host)

The Debian package already installed the hardened unit. Start it only after the assistant reports
success:

```bash
sudo systemctl enable --now retentionops-connector
sudo systemctl status retentionops-connector
sudo journalctl -u retentionops-connector -f
```

The provided unit runs as `retentionops`, permits writes only under `/var/lib/retentionops`, drops
Linux capabilities and enables systemd hardening controls. It restarts after a failure. Stop it
before rotating or removing its identity or state volume; do not delete the replay ledger during a
normal redeploy.

### Docker Compose

Use the supplied [Docker Compose](../deploy/docker/compose.yaml) as a reviewed deployment template.
Replace `REPLACE_ME` with a verified image digest, mount the configuration, CA and credentials
read-only, and use persistent storage for `/var/lib/retentionops`.

The signed OCI image may be integrated into Kubernetes by a customer, but RetentionOps does not
publish or maintain a Kubernetes manifest in the initial support scope.

Run exactly one replica per connector identity. Two replicas with independent replay ledgers can
accept the same delivered job; two replicas sharing a ledger add no useful throughput because the
connector processes one job at a time. Do not publish a container port merely to reach the
connector; configure Prometheus networking explicitly if you expose metrics.

## 8. Normal operation and changes

When running, the connector sends heartbeats and long-polls the control plane. An idle long poll
is normal; no inbound service is opened. Signed results carry counts, byte estimates, boundary
timestamps, schema metadata and stable status codes—not rows, credentials, connection strings or
driver error messages.

Use these local checks after any host, network, certificate, credential or configuration change:

```bash
sudo -u retentionops retentionops-connector validate-config --config /etc/retentionops/connector.yaml
sudo -u retentionops retentionops-connector doctor --config /etc/retentionops/connector.yaml
sudo systemctl restart retentionops-connector
sudo systemctl status retentionops-connector
```

For a safety-policy change, use a change review: edit the file locally, validate it, record the
new digest, run `source test`, then restart the service. The control plane cannot reload or widen
the policy for you. Lowering timeouts is safe because it only causes earlier failure; expanding a
table, column, row or batch allowance is a local authorisation change and should be reviewed as
such.

For credential rotation, replace the protected secret value, re-run `source test` and restart the
service. Do not rotate the connector identity casually: it binds the enrolled connector to its
pinned control-plane key and is also used to sign evidence. If it is compromised or lost, revoke
the connector through the control-plane workflow and enroll a new identity.

### Store or replace a database password

```bash
sudo retentionops-connector secret set --role reader
```

The password is asked for at a masked prompt: it never travels as an argument, so it reaches
neither the process list nor your shell history. The command writes the file that source's own
configuration names, atomically, mode `0400`, owned by the `retentionops` account — the same shape
the file provider requires and the assistant produces.

Add `--source UUID` when the connector serves several sources, `--role executor` for the identity
that deletes, and `--from-file PATH` for unattended installation (the file must be unreadable by
group and other). A source whose password is resolved through `env` or `aws-secrets-manager` is
refused rather than shadowed by a file the connector would not read.

Nothing is sent anywhere and no restart is needed: the password is resolved on each connection.
Whether PostgreSQL accepts it is answered by the connection test, from a signed result.

### Observability

With `metrics_address: 127.0.0.1:9102`, metrics are available locally at
`http://127.0.0.1:9102/metrics`. Useful signals include:

- `retentionops_connector_up` — process health;
- `retentionops_connector_last_heartbeat_seconds` — last accepted heartbeat;
- `retentionops_connector_control_plane_requests_total` — polling outcomes;
- `retentionops_connector_denials_total` — jobs refused by stable code; and
- `retentionops_connector_jobs_total`, `retentionops_connector_rows_deleted_total`, and
  `retentionops_connector_batches_total` — completed activity.

Logs and metrics stay in your environment. They must not be copied unredacted to external support:
although the connector does not send driver details upstream, local logs may contain deployment
context useful to an attacker.

## 9. Troubleshooting and recovery

| Symptom | First check | Safe response |
|---|---|---|
| `doctor` reports identity storage failure | Owner and `0700` mode of `identity.directory` | Restore directory permissions; do not replace `identity.json` |
| Control-plane DNS or HTTPS fails | DNS, proxy and egress 443 | Check `HTTPS_PROXY` and proxy CA configuration, then run `doctor` again |
| PostgreSQL TLS fails | Hostname, CA file and `verify-full` certificate SAN | Correct the database certificate/host configuration; do not downgrade TLS by default |
| Authentication fails | Reader/executor grants and secret references | Store the password again with `secret set`, then rerun `source test` |
| `SECRET_UNAVAILABLE` in the console | Whether a password file exists where the source's configuration names one | Run `secret set --role reader`; the console ticks the step from the next signed test |
| `DENIED_TARGET_NOT_ALLOWED` | Local `safety.tables` allow-list | Treat as expected containment; deliberately amend, validate and restart only if the table should be reachable |
| `DENIED_ROW_LIMIT_EXCEEDED` or `DENIED_BATCH_LIMIT_EXCEEDED` | Local ceiling versus requested scope | Raise the ceiling deliberately or re-plan; the connector will not clamp it |
| `DENIED_APPROVAL_REQUIRED` | `require_approval` and approval state | Obtain a valid approval; do not disable the local requirement as a workaround |
| `PLAN_STALE` | Current count versus the approved plan | Re-plan and re-approve; the connector did not delete beyond the approved drift tolerance |
| Repeated job expiry/refusal | NTP status and host time | Correct the clock, then wait for a newly issued job |

Do not delete `/var/lib/retentionops/state` to clear an error. It is the anti-replay ledger; losing
it weakens the protection against a captured job being accepted again within its validity window.
If storage must be recovered, stop the service, restore the persistent volume from a controlled
backup and run `doctor` before starting it.

For a suspected vulnerability, follow [SECURITY.md](../SECURITY.md) rather than opening a public
issue. For detailed rationale and field-by-field references, see
[configuration.md](configuration.md), [networking.md](networking.md),
[postgres.md](postgres.md), [security.md](security.md) and [protocol.md](protocol.md).

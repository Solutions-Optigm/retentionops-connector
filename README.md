# RetentionOps Connector

[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The RetentionOps Connector applies data-retention decisions **inside your network**, to databases
whose credentials RetentionOps never holds.

RetentionOps is a hosted service: it validates retention policies, plans what would be deleted,
routes the plan through human approval, and keeps the evidence. It does all of that without a
route to your database. The connector is the piece that has one — so it is the piece we made open
source, because "trust us, the agent is safe" is not an argument that survives a security review.

```
        RetentionOps control plane                  YOUR NETWORK
        (hosted, proprietary)
                                      ┌────────────────────────────────────────┐
   policy → plan → approval           │                                        │
              │                       │   ┌──────────────────────────────┐     │
              │  signed job           │   │  retentionops-connector      │     │
              └──────────────────────►│   │                              │     │
                    HTTPS 443         │   │  1. verify signature         │     │
                 outbound only,       │   │  2. check LOCAL policy       │     │
                 initiated here ──────┼───┤  3. resolve secret locally   │     │
                                      │   │  4. run one closed operation │     │
              ◄───────────────────────│   │  5. sign the evidence        │     │
                 counts, not rows     │   └──────────────┬───────────────┘     │
                                      │                  │ TLS verify-full     │
                                      │           ┌──────▼───────┐             │
                                      │           │  PostgreSQL  │             │
                                      │           └──────────────┘             │
                                      └────────────────────────────────────────┘
```

**No inbound port.** The connector dials out on 443 and long-polls. Your firewall needs no rule,
no forward and no exception.

## The four claims you can verify in this repository

Every one of these is a property of the code in front of you, not a policy commitment.

**1. RetentionOps cannot run SQL of its choosing.**
The wire protocol has four operations — [`protocol/v1/job.schema.json`](protocol/v1/job.schema.json)
— and no field anywhere that carries SQL, a script, a command or a path. Every statement the
connector can emit is written out in one file:
[`adapters/postgres/sql.go`](adapters/postgres/sql.go).

**2. RetentionOps cannot reach a table you did not allow-list.**
The local safety policy in your own configuration file decides. There is no protocol message that
reads or writes it. See [`internal/policy/policy.go`](internal/policy/policy.go) and the refusal
cases in [`policy_test.go`](internal/policy/policy_test.go).

**3. RetentionOps never receives your data.**
The result schema has no member that can hold a row. Counts, byte estimates, boundary timestamps,
column names and a server version — that is the whole of it:
[`protocol/v1/result.schema.json`](protocol/v1/result.schema.json).

**4. RetentionOps never receives your credentials.**
Secret references are resolved here, by this process, through your secret manager. A password has
no representation anywhere in the protocol: [`secrets/`](secrets/).

## Quick start

```bash
# 1. Install the binary (or use ghcr.io/solutions-optigm/retentionops-connector)
make build

# 2. Write /etc/retentionops/connector.yaml — start from examples/postgres/connector.yaml
retentionops-connector validate-config --config /etc/retentionops/connector.yaml

# 3. Enrol, with the one-time token from the RetentionOps console
retentionops-connector enroll \
  --url https://connector.retentionops.ca \
  --organization 3f2b9c14-8e1a-4b6d-9a7c-2d5e0f183b44 \
  --token rtc_...

# 4. Check everything before you start it
retentionops-connector doctor

# 5. Run it
retentionops-connector run
```

`doctor` walks the same code paths the running connector does, in the order a packet would meet
them, so the first `FAIL` is the thing to fix:

```
Configuration              PASS  1 source(s) declared
Local policy               PASS  sha256:6f0c…
Identity storage           PASS  /var/lib/retentionops/identity
Connector identity         PASS  connector 9d1e… in organization 3f2b…
Pinned control-plane key   PASS  MCowBQYD…kJv7Qg=
Control plane DNS          PASS  connector.retentionops.ca
Control plane HTTPS        PASS  TLS established, HTTP 404
Source 4a9f2c11 TCP        PASS  db.production.internal:5432
Source 4a9f2c11 reader…    PASS  resolved through aws-secrets-manager
Source 4a9f2c11 PostgreSQL PASS  server 16.4, tls verify-full
```

## Configuration

One file. It names where your databases are, which two identities may be used against them, and —
the important part — what RetentionOps is allowed to do there.

```yaml
control_plane:
  url: https://connector.retentionops.ca

identity: { directory: /var/lib/retentionops/identity }
state:    { directory: /var/lib/retentionops/state }

sources:
  4a9f2c11-6b3d-4e58-9f21-7c0a8d4e6b52:
    type: postgresql
    host: db.production.internal
    database: production
    tls:
      mode: verify-full
      ca_file: /etc/retentionops/certs/postgres-ca.pem

    reader:
      username: retentionops_reader
      password: { provider: aws-secrets-manager, ref: prod/retentionops/reader#password }
    executor:
      username: retentionops_executor
      password: { provider: aws-secrets-manager, ref: prod/retentionops/executor#password }

    # Everything below this line is yours. RetentionOps has no way to read it or change it.
    safety:
      allowed_schemas: [application]
      require_approval: true
      drift:
        mode: bounded
        exact_match_below_rows: 1000
        max_basis_points: 50  # 0.5%; the signed protocol remains integer-only
        max_rows: 100
      statement_timeout_seconds: 30
      lock_timeout_seconds: 5
      tables:
        - schema: application
          table: audit_logs
          actions: [inspect, delete]
          retention_columns: [created_at]
          max_delete_rows: 50000
          max_batch_size: 1000
        - schema: application
          table: users
          actions: [inspect]          # inspect only: a delete here is refused locally
```

Ask RetentionOps to delete from `application.users` and the connector answers
`DENIED_TARGET_NOT_ALLOWED` — with a signed record of having been asked.

Full reference: [`docs/configuration.md`](docs/configuration.md).

## Documentation

| | |
|---|---|
| [architecture.md](docs/architecture.md) | What runs where, and why the split is drawn there |
| [security.md](docs/security.md) | Trust boundaries, key handling, what we can and cannot do |
| [threat-model.md](docs/threat-model.md) | The attacks this design is built against, control by control |
| [protocol.md](docs/protocol.md) | Wire format, signing, canonical JSON — enough to reimplement |
| [postgres.md](docs/postgres.md) | Roles, grants, TLS, batching, what the statements actually do |
| [networking.md](docs/networking.md) | Egress rules, proxies, air-gapped notes |
| [configuration.md](docs/configuration.md) | Every field |
| [installation-and-operation.md](docs/installation-and-operation.md) | End-to-end setup, supervision and operations tutorial |
| [releases.md](docs/releases.md) | Verifying signatures, SBOMs and digests before you deploy |

## Building

Go 1.25 or later. Two dependencies: a PostgreSQL driver and a YAML parser.

```bash
make deps    # resolve the module graph (writes go.sum)
make check   # gofmt + go vet + go test -race
make dist    # reproducible binaries for linux/amd64 and linux/arm64 + checksums
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions that widen what a control plane can ask for
are held to a much higher bar than anything else here, and the reason is in that file.

## Licence

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md).

The RetentionOps control plane is a separate proprietary product of Solutions Optigm inc. and is
**not** in this repository. You do not need it to read, build, audit, modify or run this
connector.

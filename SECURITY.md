# Security policy

This component runs inside customer networks and holds credentials that can delete production
data. Treat findings here as high severity by default.

## Reporting a vulnerability

Email **security@optigm.ca**. Please do not open a public issue for a suspected vulnerability.

Include what you have: affected version, configuration shape, and the smallest reproduction you
can manage. If you have a proof of concept that deletes data, describe it rather than attaching
it.

We acknowledge within 3 business days and aim to ship a fix or a documented mitigation within 30
days for anything that lets a report below become true.

## What counts as a vulnerability here

Anything that breaks one of these properties is in scope, regardless of how unlikely the path
looks:

| Property | Why it matters |
|---|---|
| A control plane cannot cause SQL of its choosing to run | The closed operation set is the primary containment boundary |
| A control plane cannot reach a table absent from the local safety policy | The customer's file is the authority, not ours |
| A control plane cannot raise its own local limits | There is deliberately no protocol message that writes the local policy |
| A destructive job without a valid approval is refused locally | The approval check is duplicated on the customer's side on purpose |
| A captured job cannot be executed twice | Nonce ledger, expiry and connector binding |
| The private key never leaves the host | It is generated locally and has no representation in the protocol |
| No row content, credential or secret reaches the control plane or the logs | The result schema has no member that could carry one |
| A signature is verified against the pinned key, over the bytes received | Not over a re-encoding of a parsed document |

Out of scope: findings that require an attacker who already has root on the connector host or
write access to its configuration file. At that point they have the database credentials
directly, and the connector is not the boundary being tested.

## Supported versions

The latest minor release receives security fixes. Because a connector is customer-operated, we
do not force updates: see [`docs/releases.md`](docs/releases.md) for how upgrades are announced
and verified.

## Hardening checklist for operators

- Run as a non-root user, with `identity.directory` mode `0700`.
- Give the reader role `SELECT` only, and the executor role `SELECT` and `DELETE` on the
  allow-listed tables only. The connector cannot escalate what your grants allow.
- Keep `tls.mode: verify-full` and pin the CA. `require` proves encryption but not identity.
- Set `max_delete_rows` and `max_batch_size` on every table that grants `delete`, at a value you
  would be comfortable losing to a mistake.
- Bind `telemetry.metrics_address` to loopback or a private interface.
- Verify the release signature and the digest before you deploy, and pin the image digest.

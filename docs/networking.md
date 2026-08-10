# Networking

## What to open

**Outbound, from the connector host:**

| Destination | Port | Why |
|---|---|---|
| `connector.retentionops.ca` | 443/tcp | The only RetentionOps endpoint |
| Your PostgreSQL host | 5432/tcp | The target |
| Your secret manager | 443/tcp | Only if using `aws-secrets-manager` |

**Inbound: nothing.** The connector opens no listening socket for RetentionOps. If you enable the
metrics listener it binds where you tell it to — use loopback or a private interface.

That is the whole firewall change. No inbound rule, no port forward, no DMZ, no VPN, no exception
for a vendor's IP range. It is the reason this design exists.

## Why long polling

The connector issues `GET /connector/v1/jobs/next?wait=30`. The control plane holds it open until
work exists or the timer expires, then answers `204`.

WebSockets and gRPC streams are technically nicer and lose in practice. A corporate forward proxy
that refuses an upgrade, a NAT that reaps idle flows at 60 seconds, a load balancer with a fixed
idle timeout — each turns a persistent connection into a reconnection state machine you get to
debug at a customer site. A plain HTTP request that sometimes takes 30 seconds passes through all
of them.

## Behind a proxy

Standard Go proxy environment variables are honoured:

```bash
HTTPS_PROXY=http://proxy.internal:3128
NO_PROXY=db.production.internal,169.254.169.254
```

Put your database and the AWS metadata endpoint in `NO_PROXY`. Sending a PostgreSQL connection
through an HTTP proxy does not work, and sending an IMDS request through one is how a credential
ends up in a proxy log.

## TLS-inspecting proxies

If your egress proxy terminates TLS, give the connector the bundle it should trust:

```yaml
control_plane:
  url: https://connector.retentionops.ca
  ca_file: /etc/retentionops/certs/corporate-root.pem
```

This affects only the connector's calls to the control plane. The database connection has its own
`tls.ca_file`, and it should not be a proxy's — nothing should be terminating TLS between the
connector and your database.

Worth stating: a proxy that inspects this traffic sees the job envelopes and the results. It
cannot forge a job, because the signature is over the payload and verified against a pinned key
the proxy does not have. It also gains nothing interesting, because there is no row data in
either direction.

## Egress allow-lists

If you allow-list by hostname, `connector.retentionops.ca` is sufficient. If you must allow-list
by address, ask support@optigm.ca for the current ranges rather than resolving the name once —
they change.

## Air-gapped networks

Not supported, and it is not a gap we intend to close. RetentionOps is a hosted control plane; a
connector that cannot reach it has nothing to do. If your database is in a segment with no egress
at all, run the connector in a segment that has egress to both, and give it a route to the
database.

## Clock

Job expiry and request signatures both depend on the clock. The connector tolerates two minutes of
skew on `issued_at`; the control plane applies a similar window to request timestamps. Run NTP. A
host whose clock has drifted by more than a few minutes will see its jobs refused as expired,
which the log reports as `DENIED_JOB_EXPIRED` rather than as anything more mysterious.

## Verifying the isolation yourself

Two checks worth running once, in front of whoever has to sign off on this:

```bash
# The connector listens on nothing but the metrics address you configured.
ss -ltnp | grep retentionops-connector

# Its only egress is the control plane, the database and (if configured) the secret manager.
sudo tcpdump -n -i any 'not port 22' -c 200
```

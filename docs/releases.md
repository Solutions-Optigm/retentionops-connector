# Releases and verification

A connector you did not verify is a connector you have to trust — which is the situation this
whole design exists to avoid. Verify before you deploy.

## What a release contains

```
retentionops-connector v0.1.0
├── retentionops-connector-linux-amd64
├── retentionops-connector-linux-arm64
├── checksums.txt
├── sbom.cdx.json                     CycloneDX inventory
├── *.sig, *.pem                      Sigstore signatures and certificates for every artifact
└── ghcr.io/solutions-optigm/retentionops-connector:v0.1.0
```

Official builds are produced only by Solutions Optigm inc. A build you compiled yourself from this
source is a legitimate use of the licence — it is simply not an official release, and the
distinction matters when an auditor asks which one is running.

## Verify a binary

```bash
sha256sum -c checksums.txt --ignore-missing

cosign verify-blob \
  --certificate retentionops-connector-linux-amd64.pem \
  --signature   retentionops-connector-linux-amd64.sig \
  --certificate-identity-regexp 'https://github\.com/solutions-optigm/retentionops-connector/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  retentionops-connector-linux-amd64
```

Apply the same command to `checksums.txt` and `sbom.cdx.json` with their matching certificate and
signature. GitHub also publishes build provenance attestations for both binaries, the checksum
manifest and the SBOM. The OCI image carries its own BuildKit provenance and SBOM attestations.

Keyless signing: there is no long-lived private key to steal, and the certificate identity
records which workflow, at which tag, produced the artifact.

## Verify the image, then pin it

```bash
cosign verify ghcr.io/solutions-optigm/retentionops-connector:v0.1.0 \
  --certificate-identity-regexp 'https://github\.com/solutions-optigm/retentionops-connector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Deploy by digest, never by tag:

```yaml
image: ghcr.io/solutions-optigm/retentionops-connector@sha256:…
```

A tag can be moved. A digest cannot, and pinning it is what turns "we verified this build" into
"we are running the build we verified".

## Reproducing a build

```bash
git checkout v0.1.0
make dist
```

`-trimpath` removes local paths and `CGO_ENABLED=0` removes the host toolchain, so the version
string is the only build-time input. Two builds of one tag produce identical bytes; compare them
against `checksums.txt`.

## Updates

**There is no automatic updater, and there will not be one.** The control plane can tell you a
newer version exists; it cannot download, replace or restart anything. A hosted service that can
silently swap the binary holding delete rights on your production database is a supply-chain
vector aimed at you, whatever its intentions — you choose what runs.

Security fixes are announced by email to the operator address on the account and published as a
GitHub security advisory.

## Version compatibility

The connector refuses a protocol version it was not built against rather than guessing. Within
protocol v1, control plane and connector may be upgraded independently and in either order. A
protocol v2 would ship as a new connector major version, and the control plane would continue
issuing v1 jobs to v1 connectors during the overlap.

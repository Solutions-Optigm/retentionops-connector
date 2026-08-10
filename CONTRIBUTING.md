# Contributing

Thank you for looking. This component is unusual, and it is worth saying how before you spend
time on a change.

## The one thing to understand first

This binary runs inside someone else's network with credentials that can delete their production
data. Its value is not that it is featureful — it is that a reviewer can read it in an afternoon
and know exactly what a remote party can make it do.

That means **the most valuable contributions here are the ones that remove capability, not the
ones that add it.** A pull request that deletes a code path, tightens a validation, or turns a
runtime check into a structural impossibility is easy to accept. A pull request that adds a new
operation is a change to the security posture of every deployment, and is reviewed that way.

## Changes that need an ADR and a security review

Open an issue before writing code if your change touches any of:

- a new member of the `operation` enum, or any new field in `protocol/v1/`;
- anything that makes the local safety policy remotely readable or writable;
- the signature scheme, the canonical JSON rules, or the replay ledger;
- anything that could put a row value, a credential or a secret reference into a result, an
  event, a heartbeat or a log line;
- a new dependency.

For a new dependency, expect the first question to be whether the code can be written against the
standard library instead. It usually can — the AWS Secrets Manager call in `secrets/aws.go` is
about 200 lines including its SigV4 signature, which is a smaller thing for a customer's security
team to review than the AWS SDK.

## Everything else

Small fixes, clearer errors, better documentation, more test cases for the refusal paths, another
secret provider, another platform: open a pull request directly.

## Ground rules

- `make check` must pass: `gofmt`, `go vet`, `go test ./... -race`.
- New behaviour comes with a test. New *refusal* behaviour comes with a table-driven test case in
  the relevant `_test.go`, next to the existing ones.
- Comments explain **why**, never **what**. A comment that paraphrases the line below it is
  noise; a comment recording a measured constraint, an avoided trap or a deliberate trade-off is
  the reason the next person will not undo your work.
- Errors that cross the network carry a stable code, never a driver message. Driver messages can
  quote row values.
- No `panic` outside of a programming-error guard that must not degrade into a query — there is
  exactly one, in `adapters/postgres/sql.go`, and it is commented.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licensing of contributions

By submitting a pull request you agree that your contribution is licensed under the Apache
License, Version 2.0, as stated in section 5 of [LICENSE](LICENSE). Please keep the `Signed-off-by`
line (`git commit -s`) — it is our record of that agreement.

## What is not in this repository

The RetentionOps control plane — planner, policy engine, scheduler, approvals, tenancy, billing,
console — is proprietary and lives elsewhere. Issues about it, or feature requests for it, belong
at support@optigm.ca rather than here. The one thing that *is* in scope for this repository is the
contract between the two: `protocol/v1/` is the whole of what the control plane may ask for, and
arguments about whether it should be able to ask for more are welcome here.

## Maintainer synchronization

The connector has one source of truth and one direction of travel: changes are reviewed in the
private development repository, then published here. Public-only commits are not merged back by
an automated bidirectional sync.

From a clean, reviewed main branch, a release maintainer prepares the exact public history with:

```bash
git subtree split --prefix=connector -b connector-public
git push git@github.com:solutions-optigm/retentionops-connector.git \
  connector-public:main
```

Before pushing, the maintainer runs `make check`, `make dist`, and the containment checks, then
inspects the split branch for private paths or names. Tags and release artifacts are created only
in the public repository, where the release workflow signs what it builds.

module github.com/solutions-optigm/retentionops-connector

go 1.25.0

// Three dependencies, on purpose.
//
// This binary runs inside a customer's network with delete rights on a production database, so
// every module it pulls in becomes something that customer's security team has to review and
// that our SBOM has to account for. Everything that could be written against the standard
// library is: the protocol, canonical JSON, Ed25519 identity, the replay ledger, the HTTP client,
// Prometheus exposition and the AWS Secrets Manager call including its SigV4 signature.
//
// What is left is a YAML parser, a PostgreSQL driver and the Go terminal helper that disables
// echo for masked input; none is reasonable to write again.
require (
	github.com/jackc/pgx/v5 v5.9.2
	golang.org/x/term v0.39.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)

package postgres

import (
	"fmt"
	"sort"
	"strings"

	"github.com/solutions-optigm/retentionops-connector/internal/config"
)

// RenderRolesSQL produces the locally reviewed bootstrap script used by init. Keeping it in the
// PostgreSQL adapter preserves the audit property that every SQL statement the connector ships
// can be found under adapters/postgres. The script prompts for credentials and grants no DELETE.
func RenderRolesSQL(database string, reader, executor config.Credential, allowedSchemas []string) string {
	schemas := append([]string(nil), allowedSchemas...)
	sort.Strings(schemas)
	var grants strings.Builder
	for _, schema := range schemas {
		fmt.Fprintf(&grants, "GRANT USAGE ON SCHEMA %s TO %s;\n", quoteBootstrapIdentifier(schema), quoteBootstrapIdentifier(reader.Username))
		fmt.Fprintf(&grants, "GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s;\n", quoteBootstrapIdentifier(schema), quoteBootstrapIdentifier(reader.Username))
	}
	return fmt.Sprintf(`\set ON_ERROR_STOP on
-- This script creates two login roles without granting any destructive table permission.
-- Passwords are prompted by psql and never stored in this file or in process arguments.
\prompt 'Password for the RetentionOps reader role: ' reader_password
\prompt 'Password for the RetentionOps executor role: ' executor_password
SELECT format('CREATE ROLE %%I LOGIN', %s)
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) \gexec
SELECT format('CREATE ROLE %%I LOGIN', %s)
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) \gexec
ALTER ROLE %s PASSWORD :'reader_password';
ALTER ROLE %s PASSWORD :'executor_password';
GRANT CONNECT ON DATABASE %s TO %s;
GRANT CONNECT ON DATABASE %s TO %s;
%s-- Add DELETE grants only after explicitly allow-listing tables in connector.yaml.
`, quoteBootstrapLiteral(reader.Username), quoteBootstrapLiteral(reader.Username),
		quoteBootstrapLiteral(executor.Username), quoteBootstrapLiteral(executor.Username),
		quoteBootstrapIdentifier(reader.Username), quoteBootstrapIdentifier(executor.Username),
		quoteBootstrapIdentifier(database), quoteBootstrapIdentifier(reader.Username),
		quoteBootstrapIdentifier(database), quoteBootstrapIdentifier(executor.Username), grants.String())
}

func quoteBootstrapIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quoteBootstrapLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}

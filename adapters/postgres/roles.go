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
	executorBlock := ""
	if executor.Username != "" {
		executorBlock = fmt.Sprintf(`\prompt 'Password for the RetentionOps executor role: ' executor_password
SELECT format('CREATE ROLE %%I LOGIN', %s)
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) \gexec
ALTER ROLE %s PASSWORD :'executor_password';
GRANT CONNECT ON DATABASE %s TO %s;
`, quoteBootstrapLiteral(executor.Username), quoteBootstrapLiteral(executor.Username),
			quoteBootstrapIdentifier(executor.Username), quoteBootstrapIdentifier(database),
			quoteBootstrapIdentifier(executor.Username))
	}
	return fmt.Sprintf(`\set ON_ERROR_STOP on
-- This script creates login roles without granting any destructive table permission.
-- Passwords are prompted by psql and never stored in this file or in process arguments.
\prompt 'Password for the RetentionOps reader role: ' reader_password
SELECT format('CREATE ROLE %%I LOGIN', %s)
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) \gexec
ALTER ROLE %s PASSWORD :'reader_password';
GRANT CONNECT ON DATABASE %s TO %s;
%s%s-- Add an executor and DELETE grants only through the explicit local execution-enablement flow.
`, quoteBootstrapLiteral(reader.Username), quoteBootstrapLiteral(reader.Username),
		quoteBootstrapIdentifier(reader.Username), quoteBootstrapIdentifier(database),
		quoteBootstrapIdentifier(reader.Username), executorBlock, grants.String())
}

// RenderExecutorSQL creates the separately reviewed destructive role and grants only the exact
// tables a local operator selected. It is generated locally and is never carried by the protocol.
func RenderExecutorSQL(database string, executor config.Credential, tables [][2]string) string {
	ordered := append([][2]string(nil), tables...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left][0]+"."+ordered[left][1] < ordered[right][0]+"."+ordered[right][1]
	})
	schemas := make(map[string]struct{}, len(ordered))
	var grants strings.Builder
	for _, table := range ordered {
		schemas[table[0]] = struct{}{}
	}
	orderedSchemas := make([]string, 0, len(schemas))
	for schema := range schemas {
		orderedSchemas = append(orderedSchemas, schema)
	}
	sort.Strings(orderedSchemas)
	for _, schema := range orderedSchemas {
		fmt.Fprintf(&grants, "GRANT USAGE ON SCHEMA %s TO %s;\n", quoteBootstrapIdentifier(schema), quoteBootstrapIdentifier(executor.Username))
	}
	for _, table := range ordered {
		fmt.Fprintf(&grants, "GRANT SELECT, DELETE ON TABLE %s.%s TO %s;\n",
			quoteBootstrapIdentifier(table[0]), quoteBootstrapIdentifier(table[1]), quoteBootstrapIdentifier(executor.Username))
	}
	return fmt.Sprintf(`\set ON_ERROR_STOP on
-- Review this exact table list before applying it. No schema-wide DELETE grant is emitted.
\prompt 'Password for the RetentionOps executor role: ' executor_password
SELECT format('CREATE ROLE %%I LOGIN', %s)
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) \gexec
ALTER ROLE %s PASSWORD :'executor_password';
GRANT CONNECT ON DATABASE %s TO %s;
%s`, quoteBootstrapLiteral(executor.Username), quoteBootstrapLiteral(executor.Username),
		quoteBootstrapIdentifier(executor.Username), quoteBootstrapIdentifier(database),
		quoteBootstrapIdentifier(executor.Username), grants.String())
}

func quoteBootstrapIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quoteBootstrapLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}

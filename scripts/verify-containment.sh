#!/bin/sh
set -eu

tree="${1:-.}"
mode="${2:-check}"

fail() {
  echo "$1" >&2
  exit 1
}

check_no_execution() {
  if grep -rn --include='*.go' -E 'os/exec|syscall\.Exec|plugin\.Open' "$1"; then
    echo "this component must never execute anything" >&2
    return 1
  fi
}

check_sql_boundary() {
  offenders=$(grep -rln --include='*.go' \
    -E '(^|[^[:alnum:]_])(SELECT|DELETE FROM|INSERT INTO|UPDATE)[[:space:]]' "$1" \
    | grep -v '/adapters/postgres/' \
    | grep -v '_test.go$' || true)
  test -z "$offenders" || {
    echo "SQL outside adapters/postgres: $offenders" >&2
    return 1
  }
}

check_operation_set() {
  jq -e '.["$defs"].operation.enum == [
    "POSTGRES_TEST_CONNECTION",
    "POSTGRES_DISCOVER",
    "POSTGRES_COUNT",
    "POSTGRES_DELETE"
  ]' "$1/protocol/v1/job.schema.json" >/dev/null || {
    echo "the operation enum changed; this needs an ADR and a security review" >&2
    return 1
  }
}

check_all() {
  check_no_execution "$1"
  check_sql_boundary "$1"
  check_operation_set "$1"
}

check_all "$tree"

if [ "$mode" = "--self-test" ]; then
  probe=$(mktemp -d "${TMPDIR:-/tmp}/retentionops-containment.XXXXXX")
  trap 'rm -rf "$probe"' EXIT HUP INT TERM

  mkdir "$probe/exec" "$probe/sql" "$probe/protocol"
  cp -R "$tree/." "$probe/exec"
  cp -R "$tree/." "$probe/sql"
  cp -R "$tree/." "$probe/protocol"

  perl -0pi -e 's/package main/package main\n\nimport _ "os\/exec"/' \
    "$probe/exec/cmd/retentionops-connector/main.go"
  if check_no_execution "$probe/exec" >/dev/null 2>&1; then
    fail "the execution containment gate accepted os/exec"
  fi

  perl -0pi -e 's/package evidence/package evidence\n\nvar containmentProbe = "SELECT secret"/' \
    "$probe/sql/internal/evidence/evidence.go"
  if check_sql_boundary "$probe/sql" >/dev/null 2>&1; then
    fail "the SQL containment gate accepted SQL outside the adapter"
  fi

  jq '.["$defs"].operation.enum += ["POSTGRES_EXPORT"]' \
    "$probe/protocol/protocol/v1/job.schema.json" >"$probe/protocol/job.schema.json"
  mv "$probe/protocol/job.schema.json" "$probe/protocol/protocol/v1/job.schema.json"
  if check_operation_set "$probe/protocol" >/dev/null 2>&1; then
    fail "the operation containment gate accepted a fifth capability"
  fi

  echo "containment self-test verified: all three prohibited changes were refused"
else
  echo "connector containment verified: $tree"
fi

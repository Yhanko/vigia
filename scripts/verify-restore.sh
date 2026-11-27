#!/usr/bin/env bash
# Verifies PostgreSQL privileges, SECURITY DEFINER ownership, RLS enforcement,
# and table row counts after an encrypted restore (CTO #31, README §16.6).
# Usage: DATABASE_URL="postgres://vigia:...@host:5432/vigia?sslmode=disable" ./scripts/verify-restore.sh
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set (admin connection string)}"

psql_q() {
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc "$1"
}

echo "1. Checking vigia_app role flags (must NOT be superuser or bypassrls)..."
ROLE_FLAGS="$(psql_q "SELECT rolsuper || '|' || rolbypassrls FROM pg_roles WHERE rolname = 'vigia_app'")"
if [ "$ROLE_FLAGS" != "f|f" ]; then
  echo "FAIL: vigia_app flags = '$ROLE_FLAGS', expected 'f|f'" >&2
  exit 1
fi

echo "2. Checking vigia_app SELECT privileges on all application tables..."
TABLES="users sessions user_tokens organizations memberships invitations teams team_members audit_logs projects environments api_credentials"
for tbl in $TABLES; do
  has_sel="$(psql_q "SELECT has_table_privilege('vigia_app', 'public.${tbl}', 'SELECT')")"
  if [ "$has_sel" != "t" ]; then
    echo "FAIL: vigia_app lacks SELECT on ${tbl}" >&2
    exit 1
  fi
done

echo "3. Checking restricted privileges (no DELETE on organizations; no UPDATE/DELETE on audit_logs)..."
for check in \
  "organizations:DELETE" \
  "projects:DELETE" \
  "api_credentials:DELETE" \
  "audit_logs:UPDATE" \
  "audit_logs:DELETE"; do
  tbl="${check%%:*}"
  priv="${check##*:}"
  has_priv="$(psql_q "SELECT has_table_privilege('vigia_app', 'public.${tbl}', '${priv}')")"
  if [ "$has_priv" != "f" ]; then
    echo "FAIL: vigia_app unexpectedly has ${priv} on ${tbl}" >&2
    exit 1
  fi
done

echo "4. Checking all SECURITY DEFINER functions in public schema..."
BAD_FUNCS="$(psql_q "
  SELECT count(*)
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_roles r ON r.oid = p.proowner
  WHERE n.nspname = 'public'
    AND p.prosecdef = true
    AND (
      r.rolname <> 'vigia_definer'
      OR NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, ARRAY[]::text[])) cfg WHERE cfg LIKE 'search_path=%')
      OR has_function_privilege('public', p.oid, 'EXECUTE')
    )
")"
if [ "$BAD_FUNCS" != "0" ]; then
  echo "FAIL: found $BAD_FUNCS non-compliant SECURITY DEFINER function(s)" >&2
  exit 1
fi

echo "5. Checking RLS enabled AND forced on all tenant-scoped tables..."
BAD_RLS="$(psql_q "
  SELECT count(*)
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname IN ('organizations','memberships','invitations','teams','team_members','audit_logs','projects','environments','api_credentials')
    AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
")"
if [ "$BAD_RLS" != "0" ]; then
  echo "FAIL: $BAD_RLS tenant table(s) missing ENABLE+FORCE ROW LEVEL SECURITY" >&2
  exit 1
fi

echo "6. Table row counts:"
for tbl in users organizations projects api_credentials audit_logs; do
  cnt="$(psql_q "SELECT count(*) FROM public.${tbl}")"
  echo "   ${tbl}: ${cnt}"
done

echo "OK: restored database passed all privilege, SECURITY DEFINER, and RLS checks."

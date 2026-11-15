\set ON_ERROR_STOP on

-- Run as the migration/schema owner *after* EF migrations.
-- The runtime password comes from the runner environment, not a SQL literal in git.
\getenv runtime_password RUNTIME_DB_PASSWORD
\if :{?runtime_password}
\else
    \echo 'Missing RUNTIME_DB_PASSWORD: refusing to provision runtime role.'
    \quit 3
\endif

-- psql's quoted variable is a SQL literal, escaped before format(%L).
-- \gexec sends the generated CREATE statement only when the role is absent.
SELECT format(
    'CREATE ROLE comuni_app_runtime LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'runtime_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'comuni_app_runtime')
\gexec

-- Fail closed if a pre-existing role has elevated capabilities or inherited role grants.
-- In particular, a member of an owner/admin role would bypass this table allowlist.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'comuni_app_runtime'
          AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'comuni_app_runtime has forbidden elevated role attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'comuni_app_runtime')
    ) THEN
        RAISE EXCEPTION 'comuni_app_runtime must not inherit memberships in other roles';
    END IF;
END
$$;

-- Rotation is intentional. No secret is printed by normal psql execution.
SELECT format(
    'ALTER ROLE comuni_app_runtime LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'runtime_password'
)
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO comuni_app_runtime', current_database())
\gexec

-- Never grant schema CREATE or DDL ownership to the application runtime.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA platform, protocol FROM comuni_app_runtime;
GRANT USAGE ON SCHEMA platform, protocol TO comuni_app_runtime;

-- Idempotent allowlist: only already-migrated tables are accessible. New migrations
-- require review and an explicit grant update; no blanket future-table privileges.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA platform, protocol FROM comuni_app_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA platform, protocol FROM comuni_app_runtime;

GRANT SELECT ON TABLE
    platform.organizations,
    platform.organization_memberships,
    platform.organization_modules,
    protocol.records
TO comuni_app_runtime;

GRANT INSERT ON TABLE
    protocol.records,
    platform.audit_events
TO comuni_app_runtime;

GRANT UPDATE (enabled) ON TABLE platform.organization_modules TO comuni_app_runtime;

-- The verifier can be invoked in RLS; it never exposes or signs data using the DB secret.
GRANT EXECUTE ON FUNCTION platform.verified_tenant_id() TO comuni_app_runtime;

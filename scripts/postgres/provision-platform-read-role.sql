\set ON_ERROR_STOP on

-- Run as schema owner ONLY after migrations including inventory view 0012.
-- Separate platform inventory principal: NEVER reuse municipal runtime role.
-- Password arrives from protected runner environment, not CLI or git.
\getenv platform_password PLATFORM_READ_DB_PASSWORD
\if :{?platform_password}
\else
    \echo 'Missing PLATFORM_READ_DB_PASSWORD: refusing to provision platform role.'
    DO $$ BEGIN RAISE EXCEPTION 'Platform provisioning refused'; END $$;
\endif

-- Reject an empty or trivially weak secret; no secret printed.
SELECT CASE WHEN length(:'platform_password') >= 32
    THEN 1 ELSE (1/0) END AS password_guard
\gset

SELECT format(
    'CREATE ROLE comuni_platform_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'platform_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'comuni_platform_reader')
\gexec

DO $guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'comuni_platform_reader'
          AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'Platform read principal has elevated attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'comuni_platform_reader')
    ) THEN
        RAISE EXCEPTION 'Platform read principal must not be member of any role';
    END IF;
END
$guard$;

SELECT format(
    'ALTER ROLE comuni_platform_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'platform_password'
)
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO comuni_platform_reader', current_database())
\gexec

REVOKE ALL ON SCHEMA platform, protocol FROM comuni_platform_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA platform, protocol FROM comuni_platform_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA platform, protocol FROM comuni_platform_reader;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA platform TO comuni_platform_reader;

-- The platform principal can read ONLY the minimal inventory projection.
GRANT SELECT ON TABLE platform.platform_organization_inventory
    TO comuni_platform_reader;

-- Query uses the already verified (issuer, subject) OIDC principal.
-- Revocation is checked again before reading tenant metadata.
GRANT EXECUTE ON FUNCTION platform.active_platform_operator_id(text,text)
    TO comuni_platform_reader;

-- Append-only audit. There is NO permission to read past global events,
-- change them or access any municipal row, membership or document.
GRANT INSERT (id, actor_subject, action, resource_type, resource_id,
              correlation_id, occurred_at)
    ON TABLE platform.platform_operator_audit_events TO comuni_platform_reader;

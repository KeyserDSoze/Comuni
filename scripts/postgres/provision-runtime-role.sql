\set ON_ERROR_STOP on

-- Owner-only offline role password provisioning (#91, ADR 0075).
-- Requires checkout root as cwd, private runner, Python3. Never echo input.
-- The client generates a SCRAM verifier and only that verifier is sent over
-- COPY STDIN. It can still be exposed to pgAudit/DDL extensions and must be
-- treated as sensitive. No production use before external logging review.
BEGIN;

DO $role_owner$
BEGIN
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organizations'::regclass
    ) THEN
        RAISE EXCEPTION 'Restricted role provisioning requires schema owner';
    END IF;
END
$role_owner$;

CREATE TEMP TABLE pg_temp.comuni_private_input (payload text NOT NULL)
ON COMMIT DROP;
\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py runtime-role' WITH (FORMAT csv)

DO $role_password$
DECLARE
    v_payload jsonb;
    v_verifier text;
BEGIN
    IF (SELECT count(*) FROM pg_temp.comuni_private_input) <> 1 THEN
        RAISE EXCEPTION 'Invalid private SCRAM verifier envelope';
    END IF;
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb
      INTO v_payload FROM pg_temp.comuni_private_input;
    v_verifier := v_payload ->> 'SCRAM_VERIFIER';
    IF v_verifier IS NULL OR length(v_verifier) <> 133
        OR left(v_verifier, 19) <> 'SCRAM-SHA-256$4096:' THEN
        RAISE EXCEPTION 'Invalid private SCRAM verifier';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='comuni_app_runtime') THEN
        EXECUTE format(
            'CREATE ROLE comuni_app_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            v_verifier);
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname='comuni_app_runtime' AND (
            rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
            OR rolbypassrls OR rolinherit OR NOT rolcanlogin)
    ) THEN
        RAISE EXCEPTION 'Restricted SQL principal has forbidden attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE member=(SELECT oid FROM pg_roles WHERE rolname='comuni_app_runtime')
    ) THEN
        RAISE EXCEPTION 'Restricted SQL principal cannot inherit other roles';
    END IF;

    -- Dynamic DDL receives a salted SCRAM verifier, not a plaintext password.
    -- The verifier itself may be logged by DDL extensions and is sensitive.
    EXECUTE format(
        'ALTER ROLE comuni_app_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
        v_verifier);
END
$role_password$;

DO $database_grant$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO comuni_app_runtime',
                   current_database());
END
$database_grant$;

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

-- Only the data needed for the Admin's fixed-size tenant-scoped summary is
-- readable. Never grant table-wide SELECT or identity-bearing columns such as
-- actor_subject, resource_id, correlation_id. Existing signed RLS still guards
-- the SELECT, and only the API's Admin policy exposes this summary over HTTP.
GRANT SELECT (id, organization_id, action, resource_type, occurred_at)
    ON TABLE platform.audit_events TO comuni_app_runtime;

GRANT UPDATE (enabled) ON TABLE platform.organization_modules TO comuni_app_runtime;

-- Least-privilege membership administration for Reader/Officer (issue #27).
-- RESTRICTIVE RLS policies in migration 0008 additionally prohibit runtime
-- INSERT/UPDATE of Admin rows even with a valid signed tenant proof.
GRANT INSERT (organization_id, subject, role, is_active, identity_issuer)
    ON TABLE platform.organization_memberships TO comuni_app_runtime;
GRANT UPDATE (is_active)
    ON TABLE platform.organization_memberships TO comuni_app_runtime;

-- The verifier can be invoked in RLS; it never exposes or signs data using the DB secret.
GRANT EXECUTE ON FUNCTION platform.verified_tenant_id() TO comuni_app_runtime;

-- Read-only platform identity predicate (#34). NEVER grant SELECT/INSERT/UPDATE
-- on platform.platform_operators: a SQL injection cannot list operator roster.
GRANT EXECUTE ON FUNCTION platform.is_active_platform_operator(text, text)
    TO comuni_app_runtime;

COMMIT;

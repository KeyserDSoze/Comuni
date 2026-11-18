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
        FROM pg_class WHERE oid = 'platform.platform_organization_inventory'::regclass
    ) THEN
        RAISE EXCEPTION 'Restricted role provisioning requires schema owner';
    END IF;
END
$role_owner$;

CREATE TEMP TABLE pg_temp.comuni_private_input (payload text NOT NULL)
ON COMMIT DROP;
\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py platform-role' WITH (FORMAT csv)

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

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='comuni_platform_reader') THEN
        EXECUTE format(
            'CREATE ROLE comuni_platform_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            v_verifier);
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname='comuni_platform_reader' AND (
            rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
            OR rolbypassrls OR rolinherit OR NOT rolcanlogin)
    ) THEN
        RAISE EXCEPTION 'Restricted SQL principal has forbidden attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE member=(SELECT oid FROM pg_roles WHERE rolname='comuni_platform_reader')
    ) THEN
        RAISE EXCEPTION 'Restricted SQL principal cannot inherit other roles';
    END IF;

    -- Dynamic DDL receives a salted SCRAM verifier, not a plaintext password.
    -- The verifier itself may be logged by DDL extensions and is sensitive.
    EXECUTE format(
        'ALTER ROLE comuni_platform_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
        v_verifier);
END
$role_password$;

DO $database_grant$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO comuni_platform_reader',
                   current_database());
END
$database_grant$;

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

COMMIT;

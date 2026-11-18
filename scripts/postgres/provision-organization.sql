\set ON_ERROR_STOP on

-- Offline, owner-only creation of one previously unknown organization.
-- An approved external change and independent reviewer are prerequisites,
-- not facts that this script can authenticate. Never run in psql echo mode.
-- The runtime PostgreSQL role MUST NOT be able to execute this operation.
\getenv provision_org COMUNI_PROVISION_ORGANIZATION_ID
\getenv provision_name COMUNI_PROVISION_ORGANIZATION_NAME
\getenv provision_ticket COMUNI_PROVISION_CHANGE_TICKET
\getenv provision_approver COMUNI_PROVISION_APPROVER

\if :{?provision_org}
\else
    \echo 'Refused: required organization identifier is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing organization provisioning input'; END $$;
\endif
\if :{?provision_name}
\else
    \echo 'Refused: required organization name is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing organization provisioning input'; END $$;
\endif
\if :{?provision_ticket}
\else
    \echo 'Refused: required change ticket is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing organization provisioning input'; END $$;
\endif
\if :{?provision_approver}
\else
    \echo 'Refused: required independent reviewer is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing organization provisioning input'; END $$;
\endif

BEGIN;

-- Fixed client-side COPY program transports exactly four allowlisted inputs
-- (UUID, municipality label, change ticket, reviewer) outside SQL literal
-- statements. Trusted checkout root required; base64(JSON) is reversible.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py provision-organization' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.provision_org',
               secret ->> 'COMUNI_PROVISION_ORGANIZATION_ID', true) AS org,
    set_config('comuni.provision_name',
               secret ->> 'COMUNI_PROVISION_ORGANIZATION_NAME', true) AS name,
    set_config('comuni.provision_ticket',
               secret ->> 'COMUNI_PROVISION_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.provision_approver',
               secret ->> 'COMUNI_PROVISION_APPROVER', true) AS approver
FROM private_json
\gset

DO $provision$
DECLARE
    v_id_text text := current_setting('comuni.provision_org', true);
    v_name text := current_setting('comuni.provision_name', true);
    v_ticket text := current_setting('comuni.provision_ticket', true);
    v_approver text := current_setting('comuni.provision_approver', true);
    v_id uuid;
    v_existing_name text;
    v_created_event_count bigint;
BEGIN
    -- Confirm exact schema/table ownership before any mutation. Runtime has
    -- neither table ownership nor INSERT on platform.organizations.
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organizations'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organization_modules'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.audit_events'::regclass
    ) THEN
        RAISE EXCEPTION 'Organization provisioning requires schema owner';
    END IF;

    IF v_id_text IS NULL OR v_id_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_id_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid organization identifier';
    END IF;
    v_id := v_id_text::uuid;

    IF v_name IS NULL OR length(v_name) NOT BETWEEN 1 AND 200
        OR v_name <> btrim(v_name) OR v_name ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Invalid organization name';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Missing or invalid external change approval reference';
    END IF;

    -- The row does not yet exist: serialize by the UUID itself. Hash collisions
    -- may serialize unrelated tenants but never mix their records.
    PERFORM pg_advisory_xact_lock(hashtextextended(v_id::text, 0));

    SELECT name INTO v_existing_name
    FROM platform.organizations
    WHERE id = v_id FOR UPDATE;

    IF FOUND THEN
        IF v_existing_name <> v_name THEN
            RAISE EXCEPTION 'Organization already exists with different attributes';
        END IF;

        -- A matching legacy/manual row must not be claimed as a retry.
        SELECT COUNT(*) INTO v_created_event_count
        FROM platform.audit_events
        WHERE organization_id = v_id
          AND resource_type = 'platform.organization'
          AND resource_id = v_id
          AND action = 'platform.organization.created';

        IF v_created_event_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM platform.organization_modules
            WHERE organization_id = v_id AND module_key = 'protocol'
        ) THEN
            RAISE EXCEPTION 'Existing organization has no verified provisioning provenance';
        END IF;

        -- Never reactivate a suspended tenant or alter any changed module
        -- settings, memberships or organization name during retries.
        RETURN;
    END IF;

    -- Empty membership roster and feature flag off enforce server-side
    -- deny-by-default until a separately approved first Admin bootstrap.
    INSERT INTO platform.organizations (id, name, is_suspended)
    VALUES (v_id, v_name, FALSE);
    INSERT INTO platform.organization_modules
        (organization_id, module_key, enabled)
    VALUES (v_id, 'protocol', FALSE);
    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_id, 'db-owner:' || current_user,
         'platform.organization.created', 'platform.organization',
         v_id, 'bootstrap:' || v_ticket, now());
END
$provision$;

COMMIT;

\set ON_ERROR_STOP on

-- OWNER-ONLY, OFFLINE registration of a NEW municipality. The operator must
-- independently verify municipality identity, authorization and the change
-- ticket before invoking psql over a private PostgreSQL connection.
-- Do NOT use -a/-e or set -x. Do not echo inputs; private COPY avoids SQL literal interpolation (#100).
\getenv register_org COMUNI_REGISTER_ORGANIZATION_ID
\getenv register_name COMUNI_REGISTER_ORGANIZATION_NAME
\getenv register_ticket COMUNI_REGISTER_CHANGE_TICKET
\getenv register_approver COMUNI_REGISTER_APPROVER

\if :{?register_org}
\else
    \echo 'Refused: required organization ID is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing registration input'; END $$;
\endif
\if :{?register_name}
\else
    \echo 'Refused: required organization name is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing registration input'; END $$;
\endif
\if :{?register_ticket}
\else
    \echo 'Refused: required change ticket is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing registration input'; END $$;
\endif
\if :{?register_approver}
\else
    \echo 'Refused: required independent reviewer is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing registration input'; END $$;
\endif

BEGIN;

-- pgAudit can include PL/pgSQL bind values in FUNCTION/WRITE audit entries
-- when pgaudit.log_parameter=on, even though the client used private COPY.
-- Refuse BEFORE receiving any sensitive COPY payload; preserve all audit
-- classes and normal statement logging under a metadata-only parameter policy.
DO $owner_audit_parameter_guard$
BEGIN
    IF lower(coalesce(current_setting('pgaudit.log_parameter', true), 'off')) = 'on' THEN
        RAISE EXCEPTION 'Owner-only identity operation requires parameter-free audit metadata';
    END IF;
END
$owner_audit_parameter_guard$;

-- Fixed, allowlisted client-side COPY program: neither UUID, municipality
-- name, change ticket nor reviewer appears in server-side SQL literals.
-- The COPY payload is reversible base64(JSON), NOT encryption. Run psql only
-- from a trusted repository checkout root, on a private connection.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py register-organization' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.register_org',
               secret ->> 'COMUNI_REGISTER_ORGANIZATION_ID', true) AS org,
    set_config('comuni.register_name',
               secret ->> 'COMUNI_REGISTER_ORGANIZATION_NAME', true) AS name,
    set_config('comuni.register_ticket',
               secret ->> 'COMUNI_REGISTER_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.register_approver',
               secret ->> 'COMUNI_REGISTER_APPROVER', true) AS approver
FROM private_json
\gset

DO $register$
DECLARE
    v_org_text text := current_setting('comuni.register_org', true);
    v_name text := current_setting('comuni.register_name', true);
    v_ticket text := current_setting('comuni.register_ticket', true);
    v_approver text := current_setting('comuni.register_approver', true);
    v_org uuid;
    v_existing_name text;
    v_registered_events bigint;
    v_matching_owner_event bigint;
BEGIN
    -- Defense in depth. A compromised municipal runtime with an otherwise
    -- signed RLS context cannot create or silently adopt organizations.
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
        RAISE EXCEPTION 'Organization registration requires schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
        RAISE EXCEPTION 'Invalid organization identifier';
    END IF;
    v_org := v_org_text::uuid;
    IF v_org = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Empty organization identifier is not allowed';
    END IF;

    -- Names are labels, NOT verified municipality IDs. No normalization may
    -- silently reassign an existing UUID to a different municipality.
    IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 3 AND 200
        OR btrim(v_name) <> v_name OR v_name ~ '[[:cntrl:]]'
        OR btrim(v_name) = '' THEN
        RAISE EXCEPTION 'Invalid organization name';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
       OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Invalid external approval reference';
    END IF;

    -- Serialization covers even organizations that do not exist yet.
    PERFORM pg_advisory_xact_lock(hashtextextended('comuni.register|' || v_org::text, 0));

    SELECT name INTO v_existing_name
      FROM platform.organizations WHERE id = v_org FOR UPDATE;

    IF FOUND THEN
        -- Idempotence requires exactly one owner-origin registration event
        -- with the original identity/name/change reference. Never silently
        -- adopt manually seeded or ambiguous audit histories.
        -- The retry is trustworthy only if ONE original registration
        -- event exists for this organization. A filtered count alone could
        -- ignore additional 'registered' events or adopt a hand-crafted
        -- row with a non-owner actor and an otherwise matching ticket.
        SELECT COUNT(*),
               COUNT(*) FILTER (
                   WHERE resource_type = 'platform.organization'
                     AND resource_id = v_org
                     AND correlation_id = 'register:' || v_ticket
                     AND actor_subject = 'db-owner:' || current_user
               )
        INTO v_registered_events, v_matching_owner_event
        FROM platform.audit_events
        WHERE organization_id = v_org
          AND action = 'platform.organization.registered';

        IF v_existing_name <> v_name OR
           v_registered_events <> 1 OR v_matching_owner_event <> 1 OR
           NOT EXISTS (
               SELECT 1 FROM platform.organization_modules
               WHERE organization_id = v_org AND module_key = 'protocol'
           ) THEN
            RAISE EXCEPTION 'Organization already registered under a different change';
        END IF;
        -- No side effects: never reactivate a suspended tenant, disable a
        -- subsequently enabled module, or overwrite memberships/audit.
        RETURN;
    END IF;

    -- New tenant has no users or activated service. First Admin OIDC is a
    -- separate owner-approved step (bootstrap-initial-admin.sql).
    INSERT INTO platform.organizations (id, name, is_suspended, is_activated)
    VALUES (v_org, v_name, FALSE, FALSE);
    INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
    VALUES (v_org, 'protocol', FALSE);
    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         'platform.organization.registered', 'platform.organization',
         v_org, 'register:' || v_ticket, now());
END
$register$;

COMMIT;

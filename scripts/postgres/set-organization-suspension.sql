\set ON_ERROR_STOP on

-- Owner-only offline transition of an EXISTING organization's suspension state.
-- Never run as comuni_app_runtime or with psql echo (-a/-e) or shell tracing.
-- Real identity, incident rationale and approvals MUST be verified externally.
-- Local COPY program requires an approved trusted checkout root (#98/ADR 0082).
\getenv lifecycle_org COMUNI_LIFECYCLE_ORGANIZATION_ID
\getenv lifecycle_action COMUNI_LIFECYCLE_ACTION
\getenv lifecycle_ticket COMUNI_LIFECYCLE_CHANGE_TICKET
\getenv lifecycle_approver COMUNI_LIFECYCLE_APPROVER
\getenv lifecycle_reason COMUNI_LIFECYCLE_REASON_CODE

\if :{?lifecycle_org}
\else
    \echo 'Refused: required organization identifier is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing lifecycle input'; END $$;
\endif
\if :{?lifecycle_action}
\else
    \echo 'Refused: required lifecycle action is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing lifecycle input'; END $$;
\endif
\if :{?lifecycle_ticket}
\else
    \echo 'Refused: required change ticket is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing lifecycle input'; END $$;
\endif
\if :{?lifecycle_approver}
\else
    \echo 'Refused: required independent approver is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing lifecycle input'; END $$;
\endif
\if :{?lifecycle_reason}
\else
    \echo 'Refused: required lifecycle reason code is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing lifecycle input'; END $$;
\endif

BEGIN;

-- A fixed local COPY helper transports exactly five allowlisted inputs
-- through the COPY protocol, not as literal values in SQL statement logs.
-- Requires psql cwd at a trusted repository root; base64 is NOT encryption.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py organization-lifecycle' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.lifecycle_org',
               secret ->> 'COMUNI_LIFECYCLE_ORGANIZATION_ID', true) AS org,
    set_config('comuni.lifecycle_action',
               secret ->> 'COMUNI_LIFECYCLE_ACTION', true) AS action,
    set_config('comuni.lifecycle_ticket',
               secret ->> 'COMUNI_LIFECYCLE_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.lifecycle_approver',
               secret ->> 'COMUNI_LIFECYCLE_APPROVER', true) AS approver,
    set_config('comuni.lifecycle_reason',
               secret ->> 'COMUNI_LIFECYCLE_REASON_CODE', true) AS reason
FROM private_json
\gset

DO $lifecycle$
DECLARE
    v_org_text text := current_setting('comuni.lifecycle_org', true);
    v_action text := current_setting('comuni.lifecycle_action', true);
    v_ticket text := current_setting('comuni.lifecycle_ticket', true);
    v_approver text := current_setting('comuni.lifecycle_approver', true);
    v_reason text := current_setting('comuni.lifecycle_reason', true);
    v_org uuid;
    v_current_suspended boolean;
    v_current_activated boolean;
    v_target_suspended boolean;
    v_event_action text;
BEGIN
    -- The runtime role has no UPDATE permission on platform.organizations.
    -- Ownership check is an explicit second gate before opening the row lock.
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organizations'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.audit_events'::regclass
    ) THEN
        RAISE EXCEPTION 'Lifecycle change requires schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid organization identifier';
    END IF;
    v_org := v_org_text::uuid;

    IF v_action NOT IN ('suspend', 'reactivate') OR v_action IS NULL THEN
        RAISE EXCEPTION 'Unknown lifecycle operation';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'
        OR v_reason IS NULL OR v_reason !~ '^[a-z][a-z0-9-]{2,39}$' THEN
        RAISE EXCEPTION 'Invalid or missing external change approval reference';
    END IF;

    v_target_suspended := (v_action = 'suspend');
    v_event_action := CASE WHEN v_target_suspended
        THEN 'platform.organization.suspended'
        ELSE 'platform.organization.reactivated' END;

    -- Both concurrent calls for one tenant serialize on its organization row.
    SELECT is_suspended, is_activated
    INTO v_current_suspended, v_current_activated
    FROM platform.organizations WHERE id = v_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Organization not found';
    END IF;
    -- A pending organization is never silently made active by reactivation,
    -- nor assigned a suspended state bypassing the approval gate.
    IF NOT v_current_activated THEN
        RAISE EXCEPTION 'Pending organization requires approved first activation';
    END IF;
    IF v_current_suspended = v_target_suspended THEN
        -- Idempotent exact target state; no duplicate audit event.
        RETURN;
    END IF;

    -- Do not touch any memberships, feature flags or personal data.
    UPDATE platform.organizations
    SET is_suspended = v_target_suspended
    WHERE id = v_org;

    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         v_event_action, 'platform.organization', v_org,
         'lifecycle:' || v_ticket, now());
END
$lifecycle$;

COMMIT;

\set ON_ERROR_STOP on

-- Owner-only approved transition from CREATED/PENDING to ACTIVE.
-- The first Admin OIDC must already be verified and bootstrapped separately.
-- Do not use psql -a/-e, shell tracing, API runtime credentials, or echo input.
\getenv activate_org COMUNI_ACTIVATE_ORGANIZATION_ID
\getenv activate_ticket COMUNI_ACTIVATE_CHANGE_TICKET
\getenv activate_approver COMUNI_ACTIVATE_APPROVER

\if :{?activate_org}
\else
    \echo 'Refused: organization ID required.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing activation input'; END $$;
\endif
\if :{?activate_ticket}
\else
    \echo 'Refused: approved change ticket required.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing activation input'; END $$;
\endif
\if :{?activate_approver}
\else
    \echo 'Refused: independent approver required.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing activation input'; END $$;
\endif

BEGIN;

-- Escaped psql literals; no dynamic SQL or leaked actor/identity data.
SELECT
    set_config('comuni.activate_org', :'activate_org', true) AS org,
    set_config('comuni.activate_ticket', :'activate_ticket', true) AS ticket,
    set_config('comuni.activate_approver', :'activate_approver', true) AS approver
\gset

DO $activation$
DECLARE
    v_org_text text := current_setting('comuni.activate_org', true);
    v_ticket text := current_setting('comuni.activate_ticket', true);
    v_approver text := current_setting('comuni.activate_approver', true);
    v_org uuid;
    v_activated boolean;
    v_suspended boolean;
BEGIN
    -- The municipal runtime must never activate an organization regardless
    -- of what it can sign or claim about its tenant context.
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organizations'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organization_memberships'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.audit_events'::regclass
    ) THEN
        RAISE EXCEPTION 'Activation requires migration/schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid organization identifier';
    END IF;
    v_org := v_org_text::uuid;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Invalid or missing external activation approval reference';
    END IF;

    -- Serialize simultaneous transitions and concurrent suspension changes.
    SELECT is_activated, is_suspended INTO v_activated, v_suspended
    FROM platform.organizations WHERE id = v_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Organization does not exist';
    END IF;
    IF v_suspended THEN
        RAISE EXCEPTION 'Suspended organization cannot be activated by onboarding';
    END IF;
    IF v_activated THEN
        -- Retry / legacy active organization: no flag/role or audit changes.
        RETURN;
    END IF;

    -- No activation if a service was accidentally enabled before the
    -- organization completed its separate first-Admin identity bootstrap.
    IF NOT EXISTS (
        SELECT 1 FROM platform.organization_modules
        WHERE organization_id = v_org AND module_key = 'protocol' AND enabled = FALSE
    ) OR EXISTS (
        SELECT 1 FROM platform.organization_modules
        WHERE organization_id = v_org AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION 'Pending organization modules are not safely disabled';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM platform.organization_memberships
        WHERE organization_id = v_org AND role = 'Admin' AND is_active = TRUE
          AND identity_issuer IS NOT NULL
          AND identity_issuer ~ '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$'
    ) THEN
        RAISE EXCEPTION 'A verified active OIDC Admin is required before activation';
    END IF;

    UPDATE platform.organizations SET is_activated = TRUE WHERE id = v_org;

    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         'platform.organization.activated', 'platform.organization',
         v_org, 'activation:' || v_ticket, now());
END
$activation$;

COMMIT;

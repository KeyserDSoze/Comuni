\set ON_ERROR_STOP on

-- OWNER-ONLY OFFLINE additional OIDC Admin enrollment (#80/#83; ADR 0069/0071).
-- The existing first Admin is NEVER disabled, transferred or replaced.
-- Independent human issuer+sub verification and change approval are required
-- before invoking this script with a private schema-owner connection.
-- Do not run with psql -a/-e, shell tracing or a municipal runtime credential.
\getenv add_admin_org COMUNI_ADD_ADMIN_ORGANIZATION_ID
\getenv add_admin_issuer COMUNI_ADD_ADMIN_IDENTITY_ISSUER
\getenv add_admin_subject COMUNI_ADD_ADMIN_SUBJECT
\getenv add_admin_ticket COMUNI_ADD_ADMIN_CHANGE_TICKET
\getenv add_admin_approver COMUNI_ADD_ADMIN_APPROVER

\if :{?add_admin_org}
\else
    \echo 'Refused: required organization input missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin enrollment input'; END $$;
\endif
\if :{?add_admin_issuer}
\else
    \echo 'Refused: required issuer input missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin enrollment input'; END $$;
\endif
\if :{?add_admin_subject}
\else
    \echo 'Refused: required subject input missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin enrollment input'; END $$;
\endif
\if :{?add_admin_ticket}
\else
    \echo 'Refused: required change ticket missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin enrollment input'; END $$;
\endif
\if :{?add_admin_approver}
\else
    \echo 'Refused: required reviewer input missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin enrollment input'; END $$;
\endif

BEGIN;

-- Literal quoting and transaction-local settings avoid SQL interpolation.
SELECT
    set_config('comuni.add_admin_org', :'add_admin_org', true) AS org,
    set_config('comuni.add_admin_issuer', :'add_admin_issuer', true) AS issuer,
    set_config('comuni.add_admin_subject', :'add_admin_subject', true) AS subject,
    set_config('comuni.add_admin_ticket', :'add_admin_ticket', true) AS ticket,
    set_config('comuni.add_admin_approver', :'add_admin_approver', true) AS approver
\gset

DO $enrollment$
DECLARE
    v_org_text text := current_setting('comuni.add_admin_org', true);
    v_issuer text := current_setting('comuni.add_admin_issuer', true);
    v_subject text := current_setting('comuni.add_admin_subject', true);
    v_ticket text := current_setting('comuni.add_admin_ticket', true);
    v_approver text := current_setting('comuni.add_admin_approver', true);
    v_org uuid;
    v_activated boolean;
    v_suspended boolean;
    v_admin_count bigint;
    v_valid_count bigint;
    v_attested_revoked_count bigint;
    v_existing_issuer text;
    v_existing_active boolean;
    v_matching_audits bigint;
    v_resource_id uuid;
    v_correlation text;
BEGIN
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
        RAISE EXCEPTION 'Admin enrollment requires the migration/schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid enrollment organization';
    END IF;
    v_org := v_org_text::uuid;

    IF v_issuer IS NULL OR length(v_issuer) > 512 OR v_issuer !~
        '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$' THEN
        RAISE EXCEPTION 'Invalid verified HTTPS OIDC issuer';
    END IF;
    IF v_subject IS NULL OR length(v_subject) NOT BETWEEN 1 AND 160
        OR v_subject <> btrim(v_subject) OR v_subject ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Invalid exact OIDC subject';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Missing or invalid independent change approval reference';
    END IF;

    -- Organization lock serializes concurrent Admin enrollment and lifecycle
    -- changes; no runtime tenant selector or API route is exposed.
    SELECT is_activated, is_suspended INTO v_activated, v_suspended
    FROM platform.organizations WHERE id = v_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Enrollment organization does not exist';
    END IF;
    IF NOT v_activated OR v_suspended THEN
        RAISE EXCEPTION 'Only an operational organization can add an Admin';
    END IF;

    -- Inactive Admins are historical only if their owner-only revocation
    -- is independently represented by exactly one matching append-only audit.
    -- No unsigned disable, legacy issuer, or unhealthy active Admin is tolerated.
    SELECT count(*),
           count(*) FILTER (
               WHERE m.is_active = TRUE AND m.identity_issuer IS NOT NULL
                 AND length(m.identity_issuer) <= 512
                 AND m.identity_issuer ~
                     '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$'),
           count(*) FILTER (
               WHERE m.is_active = FALSE AND m.identity_issuer IS NOT NULL
                 AND length(m.identity_issuer) <= 512
                 AND m.identity_issuer ~
                     '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$'
                 AND (SELECT count(*) FROM platform.audit_events a
                      WHERE a.organization_id = v_org
                        AND a.action = 'platform.membership.admin.revoked'
                        AND a.resource_type = 'platform.membership'
                        AND a.resource_id = md5(
                            v_org::text || '|Admin|' || m.subject || '|' || m.identity_issuer
                        )::uuid
                        AND a.correlation_id ~
                            '^admin-revoke:[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
                        AND a.actor_subject LIKE 'db-owner:%') = 1)
      INTO v_admin_count, v_valid_count, v_attested_revoked_count
      FROM platform.organization_memberships m
     WHERE m.organization_id = v_org AND m.role = 'Admin';
    IF v_valid_count < 1 OR v_admin_count <> v_valid_count + v_attested_revoked_count THEN
        RAISE EXCEPTION 'An active OIDC Admin and fully audited revoked history are required';
    END IF;

    v_resource_id := md5(v_org::text || '|Admin|' || v_subject || '|' || v_issuer)::uuid;
    v_correlation := 'admin-enroll:' || v_ticket;

    SELECT count(*) INTO v_matching_audits FROM platform.audit_events
    WHERE organization_id = v_org AND action = 'platform.membership.admin.added'
      AND resource_type = 'platform.membership'
      AND resource_id = v_resource_id AND correlation_id = v_correlation;

    -- Reusing an approval ticket for a different enrollment is forbidden.
    IF EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND action = 'platform.membership.admin.added'
          AND correlation_id = v_correlation AND resource_id <> v_resource_id
    ) THEN
        RAISE EXCEPTION 'Approval reference already belongs to another enrollment';
    END IF;

    -- Reusing a bootstrap or revocation ticket must not create a new grant.
    IF EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND resource_type = 'platform.membership'
          AND ((action = 'platform.membership.admin.initialized'
                AND correlation_id = 'bootstrap:' || v_ticket)
            OR (action = 'platform.membership.admin.revoked'
                AND correlation_id = 'admin-revoke:' || v_ticket))
    ) THEN
        RAISE EXCEPTION 'The approval reference belongs to another Admin change';
    END IF;

    SELECT identity_issuer, is_active INTO v_existing_issuer, v_existing_active
    FROM platform.organization_memberships
    WHERE organization_id = v_org AND role = 'Admin' AND subject = v_subject;

    IF FOUND THEN
        IF v_existing_active = TRUE AND v_existing_issuer = v_issuer
            AND v_matching_audits = 1 THEN
            RETURN; -- Exact retry, no new audit or permission change.
        END IF;
        RAISE EXCEPTION 'Admin enrollment already exists or requires a separate change';
    END IF;

    IF v_matching_audits <> 0 OR EXISTS (
        SELECT 1 FROM platform.organization_memberships
        WHERE organization_id = v_org AND subject = v_subject
    ) OR EXISTS (
        -- If a historical target was illicitly deleted, its audit fingerprint
        -- must not become a fresh Admin grant.
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND resource_type = 'platform.membership'
          AND resource_id = v_resource_id
          AND action IN ('platform.membership.admin.initialized',
                         'platform.membership.admin.added',
                         'platform.membership.admin.revoked')
    ) THEN
        RAISE EXCEPTION 'Unapproved or conflicting subject enrollment';
    END IF;

    INSERT INTO platform.organization_memberships
        (organization_id, subject, role, identity_issuer, is_active)
    VALUES (v_org, v_subject, 'Admin', v_issuer, TRUE);

    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES (gen_random_uuid(), v_org, 'db-owner:' || current_user,
        'platform.membership.admin.added', 'platform.membership',
        v_resource_id, v_correlation, now());
END
$enrollment$;

COMMIT;

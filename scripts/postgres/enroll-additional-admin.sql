\set ON_ERROR_STOP on

-- OWNER-ONLY OFFLINE additional OIDC Admin enrollment (#80/#83/#87; ADR 0069/0071/0077).
-- The existing first Admin is NEVER disabled, transferred or replaced.
-- Independent human issuer+sub verification and change approval are required
-- before invoking this script with a private schema-owner connection.
-- Do not run with psql -a/-e, shell tracing or a municipal runtime credential.
-- The private COPY helper must run from a trusted checkout root (#94, ADR 0078).
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

-- Values are read through a fixed, local, client-side COPY STDIN program:
-- no issuer, subject or ticket is interpolated into server SQL statements.
-- Requires a trusted checkout with psql cwd at repository root.
-- Base64(JSON) is only transport encoding, not encryption or anonymization.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py add-admin' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.add_admin_org',
               secret ->> 'COMUNI_ADD_ADMIN_ORGANIZATION_ID', true) AS org,
    set_config('comuni.add_admin_issuer',
               secret ->> 'COMUNI_ADD_ADMIN_IDENTITY_ISSUER', true) AS issuer,
    set_config('comuni.add_admin_subject',
               secret ->> 'COMUNI_ADD_ADMIN_SUBJECT', true) AS subject,
    set_config('comuni.add_admin_ticket',
               secret ->> 'COMUNI_ADD_ADMIN_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.add_admin_approver',
               secret ->> 'COMUNI_ADD_ADMIN_APPROVER', true) AS approver
FROM private_json
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
    v_valid_count bigint;
    v_admin record;
    v_revocation_count bigint;
    v_revocation_action text;
    v_revocation_correlation text;
    v_revocation_actor text;
    v_revocation_time timestamptz;
    v_stage_count bigint;
    v_lifecycle_action text;
    v_lifecycle_time timestamptz;
    v_lifecycle_actor text;
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

    -- All active Admins must remain bound to an OIDC issuer; at least one is
    -- required before any owner-only enrollment. Never infer identity from JWT
    -- role claims or from a tenant-supplied selector.
    SELECT count(*) INTO v_valid_count
    FROM platform.organization_memberships m
    WHERE m.organization_id = v_org AND m.role = 'Admin'
      AND m.is_active = TRUE AND m.identity_issuer IS NOT NULL
      AND length(m.identity_issuer) <= 512
      AND m.identity_issuer ~
          '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$';
    IF v_valid_count < 1 THEN
        RAISE EXCEPTION 'An active issuer-bound OIDC Admin is required';
    END IF;

    -- Every historical Admin is individually checked against exactly ONE
    -- owner-only revoke audit for its exact org|role|subject|issuer hash.
    -- A break-glass revoke must additionally be paired atomically with
    -- the staged, CURRENT active Admin and an independently audited
    -- reactivation AFTER that incident. Neither record is rewritten.
    FOR v_admin IN
        SELECT subject, identity_issuer, is_active
        FROM platform.organization_memberships
        WHERE organization_id = v_org AND role = 'Admin'
    LOOP
        IF v_admin.identity_issuer IS NULL OR length(v_admin.identity_issuer) > 512
           OR v_admin.identity_issuer !~
               '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$' THEN
            RAISE EXCEPTION 'Ambiguous historical or active Admin identity';
        END IF;
        IF v_admin.is_active = FALSE THEN
            SELECT count(*) INTO v_revocation_count
            FROM platform.audit_events a
            WHERE a.organization_id = v_org
              AND a.resource_type = 'platform.membership'
              AND a.resource_id = md5(
                  v_org::text || '|Admin|' || v_admin.subject || '|' || v_admin.identity_issuer
              )::uuid
              AND a.action IN ('platform.membership.admin.revoked',
                               'platform.membership.admin.emergency.revoked');
            IF v_revocation_count <> 1 THEN
                RAISE EXCEPTION 'Historical Admin requires one exact revocation audit';
            END IF;
            SELECT action, correlation_id, actor_subject, occurred_at
              INTO v_revocation_action, v_revocation_correlation,
                   v_revocation_actor, v_revocation_time
            FROM platform.audit_events a
            WHERE a.organization_id = v_org
              AND a.resource_type = 'platform.membership'
              AND a.resource_id = md5(
                  v_org::text || '|Admin|' || v_admin.subject || '|' || v_admin.identity_issuer
              )::uuid
              AND a.action IN ('platform.membership.admin.revoked',
                               'platform.membership.admin.emergency.revoked');
            IF v_revocation_actor NOT LIKE 'db-owner:%' THEN
                RAISE EXCEPTION 'Revocation audit must be owner-originated';
            END IF;

            IF v_revocation_action = 'platform.membership.admin.revoked' THEN
                IF v_revocation_correlation !~
                   '^admin-revoke:[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$' THEN
                    RAISE EXCEPTION 'Invalid normal Admin revocation audit';
                END IF;
            ELSIF v_revocation_action = 'platform.membership.admin.emergency.revoked' THEN
                IF v_revocation_correlation !~ '^emergency:INC-[A-Za-z0-9-]{8,60}$'
                   OR (SELECT count(*) FROM platform.audit_events a
                       WHERE a.organization_id = v_org
                         AND a.correlation_id = v_revocation_correlation) <> 2 THEN
                    RAISE EXCEPTION 'Emergency incident audit must be unique and complete';
                END IF;
                SELECT count(*) INTO v_stage_count
                FROM platform.audit_events a
                JOIN platform.organization_memberships m
                  ON m.organization_id = v_org AND m.role = 'Admin'
                 AND m.is_active = TRUE
                 AND a.resource_id = md5(
                     v_org::text || '|Admin|' || m.subject || '|' || m.identity_issuer
                 )::uuid
                WHERE a.organization_id = v_org
                  AND a.action = 'platform.membership.admin.emergency.staged'
                  AND a.correlation_id = v_revocation_correlation
                  AND a.resource_type = 'platform.membership'
                  AND a.actor_subject = v_revocation_actor
                  AND a.occurred_at = v_revocation_time;
                IF v_stage_count <> 1 OR EXISTS (
                    SELECT 1 FROM platform.organization_memberships m
                    WHERE m.organization_id = v_org
                      AND m.subject = v_admin.subject AND m.role <> 'Admin'
                ) THEN
                    RAISE EXCEPTION 'Emergency staged Admin pair or containment is invalid';
                END IF;

                SELECT action, occurred_at, actor_subject
                  INTO v_lifecycle_action, v_lifecycle_time, v_lifecycle_actor
                FROM platform.audit_events
                WHERE organization_id = v_org
                  AND resource_type = 'platform.organization'
                  AND resource_id = v_org
                  AND action IN ('platform.organization.suspended',
                                 'platform.organization.reactivated')
                ORDER BY occurred_at DESC, id DESC LIMIT 1;
                IF v_lifecycle_action IS DISTINCT FROM 'platform.organization.reactivated'
                   OR v_lifecycle_time IS NULL
                   OR v_lifecycle_time < v_revocation_time
                   OR v_lifecycle_actor NOT LIKE 'db-owner:%' THEN
                    RAISE EXCEPTION 'Independently audited post-incident reactivation required';
                END IF;
            ELSE
                RAISE EXCEPTION 'Unsupported historical Admin revocation';
            END IF;
        END IF;
    END LOOP;

    -- Fail closed for orphan, forged or duplicate emergency events, including
    -- events not reachable via a historical membership. Both sides must be
    -- owner-originated in the same transaction (same occurred_at and actor).
    IF EXISTS (
        SELECT 1 FROM platform.audit_events a
        WHERE a.organization_id = v_org
          AND a.action IN ('platform.membership.admin.emergency.revoked',
                           'platform.membership.admin.emergency.staged')
          AND (
              a.resource_type <> 'platform.membership'
              OR a.actor_subject NOT LIKE 'db-owner:%'
              OR a.correlation_id !~ '^emergency:INC-[A-Za-z0-9-]{8,60}$'
              OR (SELECT count(*) FROM platform.audit_events e
                  WHERE e.organization_id = v_org
                    AND e.correlation_id = a.correlation_id) <> 2
              OR NOT EXISTS (
                  SELECT 1 FROM platform.audit_events paired
                  WHERE paired.organization_id = v_org
                    AND paired.correlation_id = a.correlation_id
                    AND paired.resource_type = 'platform.membership'
                    AND paired.actor_subject = a.actor_subject
                    AND paired.occurred_at = a.occurred_at
                    AND paired.action = CASE
                        WHEN a.action = 'platform.membership.admin.emergency.revoked'
                          THEN 'platform.membership.admin.emergency.staged'
                        ELSE 'platform.membership.admin.emergency.revoked' END)
              OR (a.action = 'platform.membership.admin.emergency.revoked'
                  AND NOT EXISTS (
                      SELECT 1 FROM platform.organization_memberships m
                      WHERE m.organization_id = v_org AND m.role = 'Admin'
                        AND m.is_active = FALSE
                        AND a.resource_id = md5(
                            v_org::text || '|Admin|' || m.subject || '|' || m.identity_issuer
                        )::uuid))
              OR (a.action = 'platform.membership.admin.emergency.staged'
                  AND NOT EXISTS (
                      SELECT 1 FROM platform.organization_memberships m
                      WHERE m.organization_id = v_org AND m.role = 'Admin'
                        AND m.is_active = TRUE
                        AND a.resource_id = md5(
                            v_org::text || '|Admin|' || m.subject || '|' || m.identity_issuer
                        )::uuid))
          )
    ) THEN
        RAISE EXCEPTION 'Unmatched or inconsistent emergency audit history';
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
                AND correlation_id = 'admin-revoke:' || v_ticket)
            OR (action IN ('platform.membership.admin.emergency.revoked',
                           'platform.membership.admin.emergency.staged')
                AND correlation_id = 'emergency:' || v_ticket))
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
                         'platform.membership.admin.revoked',
                         'platform.membership.admin.emergency.revoked',
                         'platform.membership.admin.emergency.staged')
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

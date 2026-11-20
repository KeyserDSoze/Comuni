\set ON_ERROR_STOP on

-- STAGED, OFFLINE, OWNER-ONLY incident recovery (#85 / ADR 0072).
-- NO IdP binding verification or approval authentication is performed here:
-- operator MUST verify municipality, identity, MFA, two reviewers and incident
-- through an independently controlled workflow BEFORE any real-world use.
-- NEVER run with psql -a/-e, tracing, or a runtime/service connection.
-- NEVER reactivate the organization in this script.
\getenv emergency_org COMUNI_EMERGENCY_ORGANIZATION_ID
\getenv emergency_old_issuer COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER
\getenv emergency_old_subject COMUNI_EMERGENCY_OLD_SUBJECT
\getenv emergency_new_issuer COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER
\getenv emergency_new_subject COMUNI_EMERGENCY_NEW_SUBJECT
\getenv emergency_ticket COMUNI_EMERGENCY_INCIDENT_TICKET
\getenv emergency_security_reviewer COMUNI_EMERGENCY_SECURITY_REVIEWER
\getenv emergency_municipal_reviewer COMUNI_EMERGENCY_MUNICIPAL_REVIEWER
\getenv emergency_reason COMUNI_EMERGENCY_REASON_CODE

\if :{?emergency_org}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_old_issuer}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_old_subject}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_new_issuer}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_new_subject}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_ticket}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_security_reviewer}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_municipal_reviewer}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif
\if :{?emergency_reason}
\else
    DO $$ BEGIN RAISE EXCEPTION 'Missing emergency input'; END $$;
\endif

BEGIN;

-- Do not consume any emergency identity/incident COPY input while pgAudit
-- would log nested PL/pgSQL parameter values. This leaves the audit classes
-- ROLE/DDL/WRITE/FUNCTION and native statement logging enabled.
DO $owner_audit_parameter_guard$
BEGIN
    IF lower(coalesce(current_setting('pgaudit.log_parameter', true), 'off')) = 'on' THEN
        RAISE EXCEPTION 'Owner-only emergency operation requires parameter-free audit metadata';
    END IF;
END
$owner_audit_parameter_guard$;

-- The *client-side* psql \copy command runs a fixed, reviewed local program.
-- The helper reads only the allowlisted environment variables, then streams
-- one base64(JSON) record to COPY STDIN. Base64 is NOT encryption: the pipe
-- and the temporary session table are sensitive. No secret occurs in SQL text.
-- Operation requires a trusted checkout and working directory at repo root.
-- Never run \copy with input-derived program name, path, SQL or arguments.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py emergency' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.emergency_org',
               secret ->> 'COMUNI_EMERGENCY_ORGANIZATION_ID', true) AS org,
    set_config('comuni.emergency_old_issuer',
               secret ->> 'COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER', true) AS old_issuer,
    set_config('comuni.emergency_old_subject',
               secret ->> 'COMUNI_EMERGENCY_OLD_SUBJECT', true) AS old_subject,
    set_config('comuni.emergency_new_issuer',
               secret ->> 'COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER', true) AS new_issuer,
    set_config('comuni.emergency_new_subject',
               secret ->> 'COMUNI_EMERGENCY_NEW_SUBJECT', true) AS new_subject,
    set_config('comuni.emergency_ticket',
               secret ->> 'COMUNI_EMERGENCY_INCIDENT_TICKET', true) AS ticket,
    set_config('comuni.emergency_security_reviewer',
               secret ->> 'COMUNI_EMERGENCY_SECURITY_REVIEWER', true) AS security_reviewer,
    set_config('comuni.emergency_municipal_reviewer',
               secret ->> 'COMUNI_EMERGENCY_MUNICIPAL_REVIEWER', true) AS municipal_reviewer,
    set_config('comuni.emergency_reason',
               secret ->> 'COMUNI_EMERGENCY_REASON_CODE', true) AS reason
FROM private_json
\gset

DO $emergency$
DECLARE
    v_org_text text := current_setting('comuni.emergency_org', true);
    v_old_issuer text := current_setting('comuni.emergency_old_issuer', true);
    v_old_subject text := current_setting('comuni.emergency_old_subject', true);
    v_new_issuer text := current_setting('comuni.emergency_new_issuer', true);
    v_new_subject text := current_setting('comuni.emergency_new_subject', true);
    v_ticket text := current_setting('comuni.emergency_ticket', true);
    v_security_reviewer text := current_setting('comuni.emergency_security_reviewer', true);
    v_municipal_reviewer text := current_setting('comuni.emergency_municipal_reviewer', true);
    v_reason text := current_setting('comuni.emergency_reason', true);
    v_org uuid;
    v_active boolean;
    v_suspended boolean;
    v_lifecycle_action text;
    v_last_suspension timestamptz;
    v_total_admins bigint;
    v_active_admins bigint;
    v_attested_inactive bigint;
    v_current_old_issuer text;
    v_old_active boolean;
    v_new_active boolean;
    v_current_new_issuer text;
    v_old_resource uuid;
    v_new_resource uuid;
    v_corr text;
    v_emergency_events bigint;
    v_old_event_count bigint;
    v_new_event_count bigint;
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
        RAISE EXCEPTION 'Emergency staging requires the migration/schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid emergency organization';
    END IF;
    v_org := v_org_text::uuid;

    IF v_old_issuer IS NULL OR length(v_old_issuer) > 512 OR v_old_issuer !~
        '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$'
      OR v_new_issuer IS NULL OR length(v_new_issuer) > 512 OR v_new_issuer !~
        '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$' THEN
        RAISE EXCEPTION 'Invalid verified OIDC issuer input';
    END IF;
    IF v_old_subject IS NULL OR length(v_old_subject) NOT BETWEEN 1 AND 160
        OR v_old_subject <> btrim(v_old_subject) OR v_old_subject ~ '[[:cntrl:]]'
        OR v_new_subject IS NULL OR length(v_new_subject) NOT BETWEEN 1 AND 160
        OR v_new_subject <> btrim(v_new_subject) OR v_new_subject ~ '[[:cntrl:]]'
        OR v_old_subject = v_new_subject THEN
        RAISE EXCEPTION 'Invalid or reused OIDC subject';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^INC-[A-Za-z0-9-]{8,60}$'
        OR v_security_reviewer IS NULL
        OR v_security_reviewer !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'
        OR v_municipal_reviewer IS NULL
        OR v_municipal_reviewer !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'
        OR lower(v_security_reviewer) = lower(v_municipal_reviewer)
        OR lower(v_security_reviewer) = lower(current_user)
        OR lower(v_municipal_reviewer) = lower(current_user)
        OR v_reason IS NULL OR v_reason !~ '^[a-z][a-z0-9-]{5,63}$' THEN
        RAISE EXCEPTION 'Invalid incident or independent review references';
    END IF;

    -- A row-level lock coordinates with the existing owner-only suspend,
    -- enrollment, and revocation scripts. All checks and writes are atomic.
    SELECT is_activated, is_suspended INTO v_active, v_suspended
    FROM platform.organizations WHERE id = v_org FOR UPDATE;
    IF NOT FOUND OR NOT v_active OR NOT v_suspended THEN
        RAISE EXCEPTION 'Emergency staging requires an existing suspended active-lifecycle organization';
    END IF;

    SELECT action, occurred_at INTO v_lifecycle_action, v_last_suspension
    FROM platform.audit_events
    WHERE organization_id = v_org AND resource_type = 'platform.organization'
      AND resource_id = v_org
      AND action IN ('platform.organization.suspended', 'platform.organization.reactivated')
      AND actor_subject LIKE 'db-owner:%'
    ORDER BY occurred_at DESC, id DESC LIMIT 1;
    IF NOT FOUND OR v_lifecycle_action <> 'platform.organization.suspended' THEN
        RAISE EXCEPTION 'An independently audited suspension is required first';
    END IF;

    v_old_resource := md5(
        v_org::text || '|Admin|' || v_old_subject || '|' || v_old_issuer)::uuid;
    v_new_resource := md5(
        v_org::text || '|Admin|' || v_new_subject || '|' || v_new_issuer)::uuid;
    v_corr := 'emergency:' || v_ticket;

    -- Exact incident replay must match both audit records and the state. It
    -- cannot be used to reactivate the tenant or to choose another identity.
    SELECT count(*) INTO v_emergency_events
    FROM platform.audit_events
    WHERE organization_id = v_org AND correlation_id = v_corr
      AND action IN ('platform.membership.admin.emergency.revoked',
                     'platform.membership.admin.emergency.staged');
    SELECT count(*) INTO v_old_event_count
    FROM platform.audit_events
    WHERE organization_id = v_org AND correlation_id = v_corr
      AND action = 'platform.membership.admin.emergency.revoked'
      AND resource_type = 'platform.membership' AND resource_id = v_old_resource;
    SELECT count(*) INTO v_new_event_count
    FROM platform.audit_events
    WHERE organization_id = v_org AND correlation_id = v_corr
      AND action = 'platform.membership.admin.emergency.staged'
      AND resource_type = 'platform.membership' AND resource_id = v_new_resource;

    SELECT identity_issuer, is_active
    INTO v_current_old_issuer, v_old_active
    FROM platform.organization_memberships
    WHERE organization_id = v_org AND subject = v_old_subject AND role = 'Admin';
    IF NOT FOUND OR v_current_old_issuer IS DISTINCT FROM v_old_issuer THEN
        RAISE EXCEPTION 'The exact compromised OIDC Admin was not found';
    END IF;

    -- Do not stage a replacement if the compromised principal has ANY
    -- other role in this municipality. After reactivation that role would
    -- still authorize the old OIDC subject. Revocation/cleanup of other
    -- roles needs its own independently reviewed, audited change.
    IF EXISTS (
        SELECT 1 FROM platform.organization_memberships
        WHERE organization_id = v_org AND subject = v_old_subject
          AND role <> 'Admin'
    ) THEN
        RAISE EXCEPTION 'Compromised identity has other membership roles';
    END IF;

    IF v_old_active IS DISTINCT FROM TRUE THEN
        IF v_emergency_events = 2 AND v_old_event_count = 1 AND v_new_event_count = 1
            AND EXISTS (
                SELECT 1 FROM platform.organization_memberships
                WHERE organization_id = v_org AND role = 'Admin'
                  AND subject = v_new_subject AND identity_issuer = v_new_issuer
                  AND is_active = TRUE
            )
            AND (
                SELECT count(*) FROM platform.organization_memberships
                WHERE organization_id = v_org AND role = 'Admin' AND is_active = TRUE
            ) = 1 THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'Inactive or ambiguously staged Admin cannot be recovered';
    END IF;
    IF v_emergency_events <> 0 THEN
        RAISE EXCEPTION 'Incident ticket was already used for another emergency';
    END IF;

    -- A valid, still-current suspension permits at most one NEW emergency
    -- transition. Subsequent transfers need a newly authorized lifecycle.
    IF EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org
          AND action = 'platform.membership.admin.emergency.staged'
          AND occurred_at >= v_last_suspension
    ) THEN
        RAISE EXCEPTION 'This suspension already has a staged emergency replacement';
    END IF;

    -- Reject reused incident numbers from other owner-only admin operations.
    IF EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND correlation_id IN (
            'bootstrap:' || v_ticket, 'admin-enroll:' || v_ticket,
            'admin-revoke:' || v_ticket, 'lifecycle:' || v_ticket)
    ) THEN
        RAISE EXCEPTION 'Incident reference already belongs to another owner change';
    END IF;

    -- Require EXACTLY one active, issuer-bound Admin. Historical revoked
    -- memberships are accepted only with one matching audit fingerprint.
    SELECT count(*),
           count(*) FILTER (WHERE m.is_active = TRUE),
           count(*) FILTER (
               WHERE m.is_active = FALSE AND m.identity_issuer IS NOT NULL
                 AND length(m.identity_issuer) <= 512
                 AND m.identity_issuer ~
                     '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$'
                 AND (SELECT count(*) FROM platform.audit_events a
                      WHERE a.organization_id = v_org
                        AND a.resource_type = 'platform.membership'
                        AND a.resource_id = md5(
                            v_org::text || '|Admin|' || m.subject || '|' || m.identity_issuer
                        )::uuid
                        AND a.action IN ('platform.membership.admin.revoked',
                                         'platform.membership.admin.emergency.revoked')
                        AND a.actor_subject LIKE 'db-owner:%'
                        AND (a.correlation_id LIKE 'admin-revoke:%'
                             OR a.correlation_id LIKE 'emergency:%')) = 1)
      INTO v_total_admins, v_active_admins, v_attested_inactive
      FROM platform.organization_memberships m
     WHERE m.organization_id = v_org AND m.role = 'Admin';
    IF v_active_admins <> 1 OR v_total_admins <> 1 + v_attested_inactive THEN
        RAISE EXCEPTION 'A sole active Admin with audited history is required';
    END IF;

    IF EXISTS (
        SELECT 1 FROM platform.organization_memberships
        WHERE organization_id = v_org AND subject = v_new_subject
    ) OR EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND resource_type = 'platform.membership'
          AND resource_id = v_new_resource AND action IN (
            'platform.membership.admin.initialized',
            'platform.membership.admin.added',
            'platform.membership.admin.revoked',
            'platform.membership.admin.emergency.revoked',
            'platform.membership.admin.emergency.staged')
    ) THEN
        RAISE EXCEPTION 'The replacement subject is not a new verified identity';
    END IF;

    UPDATE platform.organization_memberships
    SET is_active = FALSE
    WHERE organization_id = v_org AND role = 'Admin' AND subject = v_old_subject
      AND identity_issuer = v_old_issuer AND is_active = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Compromised Admin changed during emergency staging';
    END IF;

    INSERT INTO platform.organization_memberships
        (organization_id, subject, role, identity_issuer, is_active)
    VALUES (v_org, v_new_subject, 'Admin', v_new_issuer, TRUE);

    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         'platform.membership.admin.emergency.revoked',
         'platform.membership', v_old_resource, v_corr, now()),
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         'platform.membership.admin.emergency.staged',
         'platform.membership', v_new_resource, v_corr, now());
END
$emergency$;

COMMIT;

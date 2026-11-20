\set ON_ERROR_STOP on

-- OWNER-ONLY OFFLINE OIDC Admin revocation. ADR 0070 / issue #81.
-- Review issuer+sub and change approval externally; do NOT run against
-- production without approved change, recovery plan and independent reviewer.
-- Never run with psql -a/-e, shell tracing or municipal runtime credentials.
-- Private client-side COPY requires a trusted checkout root (ADR 0080 / #96).
\getenv revoke_org COMUNI_REVOKE_ADMIN_ORGANIZATION_ID
\getenv revoke_issuer COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER
\getenv revoke_subject COMUNI_REVOKE_ADMIN_SUBJECT
\getenv revoke_ticket COMUNI_REVOKE_ADMIN_CHANGE_TICKET
\getenv revoke_approver COMUNI_REVOKE_ADMIN_APPROVER
\getenv revoke_reason COMUNI_REVOKE_ADMIN_REASON_CODE

\if :{?revoke_org}
\else
    \echo 'Refused: missing Admin revocation organization.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif
\if :{?revoke_issuer}
\else
    \echo 'Refused: missing Admin revocation issuer.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif
\if :{?revoke_subject}
\else
    \echo 'Refused: missing Admin revocation subject.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif
\if :{?revoke_ticket}
\else
    \echo 'Refused: missing Admin revocation change ticket.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif
\if :{?revoke_approver}
\else
    \echo 'Refused: missing Admin revocation reviewer.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif
\if :{?revoke_reason}
\else
    \echo 'Refused: missing Admin revocation reason code.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing Admin revocation input'; END $$;
\endif

BEGIN;

-- PL/pgSQL values in owner-only WRITE statements can be exposed by pgAudit
-- parameter logging despite a private client-side COPY transport. Reject the
-- unsafe audit profile before receiving any private COPY payload; preserve
-- all audit classes and native SQL statement logging in the tested session.
DO $owner_audit_parameter_guard$
BEGIN
    IF lower(coalesce(current_setting('pgaudit.log_parameter', true), 'off')) = 'on' THEN
        RAISE EXCEPTION 'Owner-only identity operation requires parameter-free audit metadata';
    END IF;
END
$owner_audit_parameter_guard$;

-- The fixed local COPY source sends exactly six inputs through the protocol
-- (not as literal issuer/sub/ticket values in the SQL statement log).
-- psql must run at a trusted repository root. Base64 is NOT encryption.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py revoke-admin' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.revoke_admin_org',
               secret ->> 'COMUNI_REVOKE_ADMIN_ORGANIZATION_ID', true) AS org,
    set_config('comuni.revoke_admin_issuer',
               secret ->> 'COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER', true) AS issuer,
    set_config('comuni.revoke_admin_subject',
               secret ->> 'COMUNI_REVOKE_ADMIN_SUBJECT', true) AS subject,
    set_config('comuni.revoke_admin_ticket',
               secret ->> 'COMUNI_REVOKE_ADMIN_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.revoke_admin_approver',
               secret ->> 'COMUNI_REVOKE_ADMIN_APPROVER', true) AS approver,
    set_config('comuni.revoke_admin_reason',
               secret ->> 'COMUNI_REVOKE_ADMIN_REASON_CODE', true) AS reason
FROM private_json
\gset

DO $revocation$
DECLARE
    v_org_text text := current_setting('comuni.revoke_admin_org', true);
    v_issuer text := current_setting('comuni.revoke_admin_issuer', true);
    v_subject text := current_setting('comuni.revoke_admin_subject', true);
    v_ticket text := current_setting('comuni.revoke_admin_ticket', true);
    v_approver text := current_setting('comuni.revoke_admin_approver', true);
    v_reason text := current_setting('comuni.revoke_admin_reason', true);
    v_org uuid;
    v_activated boolean;
    v_suspended boolean;
    v_existing_issuer text;
    v_existing_active boolean;
    v_remaining_valid bigint;
    v_resource uuid;
    v_correlation text;
    v_matching_audits bigint;
BEGIN
    -- No SECURITY DEFINER or runtime RLS bypass. Only the schema migration owner
    -- can disable an Admin after an independently approved change.
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
        RAISE EXCEPTION 'Admin revocation requires the migration/schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid revocation organization';
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
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'
        OR v_reason IS NULL OR v_reason !~ '^[a-z][a-z0-9-]{5,63}$' THEN
        RAISE EXCEPTION 'Missing or invalid independent revocation approval';
    END IF;

    -- Serializes overlapping revocations for one organization. Two writers
    -- cannot each observe the other as the last surviving Admin.
    SELECT is_activated, is_suspended INTO v_activated, v_suspended
    FROM platform.organizations WHERE id = v_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Revocation organization does not exist';
    END IF;
    IF NOT v_activated OR v_suspended THEN
        RAISE EXCEPTION 'Revocation requires an operational organization';
    END IF;

    v_resource := md5(v_org::text || '|Admin|' || v_subject || '|' || v_issuer)::uuid;
    v_correlation := 'admin-revoke:' || v_ticket;
    SELECT count(*) INTO v_matching_audits FROM platform.audit_events
    WHERE organization_id = v_org AND action = 'platform.membership.admin.revoked'
      AND resource_type = 'platform.membership'
      AND resource_id = v_resource AND correlation_id = v_correlation;

    IF EXISTS (
        SELECT 1 FROM platform.audit_events
        WHERE organization_id = v_org AND action = 'platform.membership.admin.revoked'
          AND correlation_id = v_correlation AND resource_id <> v_resource
    ) THEN
        RAISE EXCEPTION 'Revocation ticket already used for another Admin';
    END IF;

    SELECT identity_issuer, is_active INTO v_existing_issuer, v_existing_active
    FROM platform.organization_memberships
    WHERE organization_id = v_org AND subject = v_subject AND role = 'Admin';
    IF NOT FOUND OR v_existing_issuer IS DISTINCT FROM v_issuer THEN
        RAISE EXCEPTION 'Exact active OIDC Admin membership was not found';
    END IF;

    IF v_existing_active = FALSE THEN
        IF v_matching_audits = 1 THEN
            RETURN; -- Exact retry only; no audit or state mutation.
        END IF;
        RAISE EXCEPTION 'Inactive Admin requires a separately reviewed recovery';
    END IF;

    IF v_existing_active IS DISTINCT FROM TRUE OR v_matching_audits <> 0 THEN
        RAISE EXCEPTION 'Ambiguous or previously revoked Admin membership';
    END IF;

    -- Count OTHER active, issuer-bound Admins under the same organization lock.
    -- Non-Admin roles and legacy/unbound or inactive Admins cannot satisfy this.
    SELECT count(*) INTO v_remaining_valid
    FROM platform.organization_memberships
    WHERE organization_id = v_org AND role = 'Admin'
      AND subject <> v_subject AND is_active = TRUE
      AND identity_issuer IS NOT NULL AND length(identity_issuer) <= 512
      AND identity_issuer ~
          '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$';
    IF v_remaining_valid < 1 THEN
        RAISE EXCEPTION 'Last verified active Admin cannot be revoked';
    END IF;

    UPDATE platform.organization_memberships
    SET is_active = FALSE
    WHERE organization_id = v_org AND role = 'Admin' AND subject = v_subject
      AND identity_issuer = v_issuer AND is_active = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Admin changed during revocation';
    END IF;

    -- Audit plus role change commit/rollback together; never expose iss/sub.
    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES (gen_random_uuid(), v_org, 'db-owner:' || current_user,
        'platform.membership.admin.revoked', 'platform.membership',
        v_resource, v_correlation, now());
END
$revocation$;

COMMIT;

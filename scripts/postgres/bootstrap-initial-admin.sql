\set ON_ERROR_STOP on

-- OWNER-ONLY, OFFLINE bootstrap of the FIRST Admin of an EXISTING organization.
-- All input values are supplied through a separately approved operator change.
-- Do not use for identity proofing, legacy backfills, second admins or runtime API.
-- Do NOT run with psql -a/-e or shell tracing; do not print input or DB responses.
-- Private COPY helper requires a trusted checkout root (ADR 0079 / #95).
\getenv bootstrap_org COMUNI_BOOTSTRAP_ORGANIZATION_ID
\getenv bootstrap_issuer COMUNI_BOOTSTRAP_IDENTITY_ISSUER
\getenv bootstrap_subject COMUNI_BOOTSTRAP_SUBJECT
\getenv bootstrap_ticket COMUNI_BOOTSTRAP_CHANGE_TICKET
\getenv bootstrap_approver COMUNI_BOOTSTRAP_APPROVER

\if :{?bootstrap_org}
\else
    \echo 'Refused: required organization input is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing bootstrap input'; END $$;
\endif
\if :{?bootstrap_issuer}
\else
    \echo 'Refused: required issuer input is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing bootstrap input'; END $$;
\endif
\if :{?bootstrap_subject}
\else
    \echo 'Refused: required subject input is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing bootstrap input'; END $$;
\endif
\if :{?bootstrap_ticket}
\else
    \echo 'Refused: required change ticket input is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing bootstrap input'; END $$;
\endif
\if :{?bootstrap_approver}
\else
    \echo 'Refused: required independent reviewer input is missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing bootstrap input'; END $$;
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

-- Client-side COPY passes exactly five private inputs into a transaction-
-- scoped TEMP table. No issuer, subject or ticket appears as a SQL literal.
-- The local command is static; psql must run from a trusted repository root.
-- Base64(JSON) is transport encoding only, not encryption or anonymization.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py bootstrap-admin' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.bootstrap_org',
               secret ->> 'COMUNI_BOOTSTRAP_ORGANIZATION_ID', true) AS org,
    set_config('comuni.bootstrap_issuer',
               secret ->> 'COMUNI_BOOTSTRAP_IDENTITY_ISSUER', true) AS issuer,
    set_config('comuni.bootstrap_subject',
               secret ->> 'COMUNI_BOOTSTRAP_SUBJECT', true) AS subject,
    set_config('comuni.bootstrap_ticket',
               secret ->> 'COMUNI_BOOTSTRAP_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.bootstrap_approver',
               secret ->> 'COMUNI_BOOTSTRAP_APPROVER', true) AS approver
FROM private_json
\gset

DO $bootstrap$
DECLARE
    v_org_text text := current_setting('comuni.bootstrap_org', true);
    v_issuer text := current_setting('comuni.bootstrap_issuer', true);
    v_subject text := current_setting('comuni.bootstrap_subject', true);
    v_ticket text := current_setting('comuni.bootstrap_ticket', true);
    v_approver text := current_setting('comuni.bootstrap_approver', true);
    v_org uuid;
    v_suspended boolean;
    v_admin_count bigint;
    v_same_admin_count bigint;
    v_membership_resource_id uuid;
BEGIN
    -- Schema owners are the only authorized callers. Not even an RLS-signed
    -- comuni_app_runtime session may grant the Admin role via this path.
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.organization_memberships'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.audit_events'::regclass
    ) THEN
        RAISE EXCEPTION 'First Admin bootstrap requires the migration/schema owner';
    END IF;

    IF v_org_text IS NULL OR v_org_text !~
        '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        OR v_org_text::uuid = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid bootstrap organization';
    END IF;
    v_org := v_org_text::uuid;

    -- Conservative canonical issuer syntax. The owner must independently
    -- verify EXACT JWT iss against HTTPS OIDC discovery before approving.
    IF v_issuer IS NULL OR length(v_issuer) > 512 OR v_issuer !~
        '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$' THEN
        RAISE EXCEPTION 'Invalid trusted HTTPS issuer input';
    END IF;
    IF v_subject IS NULL OR length(v_subject) NOT BETWEEN 1 AND 160
        OR v_subject <> btrim(v_subject) OR v_subject ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Invalid exact OIDC subject input';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Missing or invalid external change approval reference';
    END IF;

    -- Serialize concurrent provisioning attempts for the SAME organization.
    -- A missing or suspended tenant is NEVER provisioned implicitly.
    SELECT is_suspended INTO v_suspended FROM platform.organizations
    WHERE id = v_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Organization does not exist';
    END IF;
    IF v_suspended THEN
        RAISE EXCEPTION 'Suspended organization cannot receive initial Admin';
    END IF;

    SELECT COUNT(*),
           COUNT(*) FILTER (WHERE subject = v_subject
                            AND identity_issuer = v_issuer AND is_active = TRUE)
      INTO v_admin_count, v_same_admin_count
      FROM platform.organization_memberships
     WHERE organization_id = v_org AND role = 'Admin';

    -- Retries for the one already-initialized Admin are safe and audit no-op.
    IF v_admin_count = 1 AND v_same_admin_count = 1 THEN
        RETURN;
    END IF;
    -- No implicit transfer of disabled, legacy NULL issuer, or other Admins.
    IF v_admin_count <> 0 THEN
        RAISE EXCEPTION 'An Admin already exists: use a separately reviewed lifecycle operation';
    END IF;

    INSERT INTO platform.organization_memberships
        (organization_id, subject, role, identity_issuer, is_active)
    VALUES (v_org, v_subject, 'Admin', v_issuer, TRUE);

    -- Pseudonymous stable resource reference; NOT anonymous (dictionary risk).
    v_membership_resource_id := md5(v_org::text || '|Admin|' || v_subject || '|' || v_issuer)::uuid;
    INSERT INTO platform.audit_events
        (id, organization_id, actor_subject, action, resource_type,
         resource_id, correlation_id, occurred_at)
    VALUES
        (gen_random_uuid(), v_org, 'db-owner:' || current_user,
         'platform.membership.admin.initialized', 'platform.membership',
         v_membership_resource_id, 'bootstrap:' || v_ticket, now());
END
$bootstrap$;

COMMIT;

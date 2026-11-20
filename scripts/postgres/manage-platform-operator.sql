\set ON_ERROR_STOP on

-- OFFLINE ONLY: schema-owner and independent external approval required.
-- This script NEVER authenticates a real IdP account, MFA or reviewer.
-- NEVER run with psql -a/-e or shell tracing; inputs are private.
-- COPY helper requires psql working directory at a trusted checkout root (#97).
\getenv operator_issuer COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER
\getenv operator_subject COMUNI_PLATFORM_OPERATOR_SUBJECT
\getenv operator_action COMUNI_PLATFORM_OPERATOR_ACTION
\getenv operator_ticket COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET
\getenv operator_approver COMUNI_PLATFORM_OPERATOR_APPROVER

\if :{?operator_issuer}
\else
    \echo 'Refused: operator issuer missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing platform operator input'; END $$;
\endif
\if :{?operator_subject}
\else
    \echo 'Refused: operator subject missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing platform operator input'; END $$;
\endif
\if :{?operator_action}
\else
    \echo 'Refused: operator action missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing platform operator input'; END $$;
\endif
\if :{?operator_ticket}
\else
    \echo 'Refused: operator change ticket missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing platform operator input'; END $$;
\endif
\if :{?operator_approver}
\else
    \echo 'Refused: operator independent reviewer missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Missing platform operator input'; END $$;
\endif

BEGIN;

-- pgAudit may expose PL/pgSQL bind values from WRITE statements even when
-- client inputs arrive via private COPY. Deny parameter-value audit logging
-- BEFORE the COPY helper runs; keep ROLE/DDL/WRITE/FUNCTION metadata active.
DO $owner_audit_parameter_guard$
BEGIN
    IF lower(coalesce(current_setting('pgaudit.log_parameter', true), 'off')) = 'on' THEN
        RAISE EXCEPTION 'Owner-only identity operation requires parameter-free audit metadata';
    END IF;
END
$owner_audit_parameter_guard$;

-- A fixed local COPY command transports exactly five allowlisted inputs,
-- not issuer/sub/ticket literals in the server SQL statement log.
-- Base64(JSON) is reversible, NOT encryption; use trusted checkout root.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py platform-operator' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.operator_issuer',
               secret ->> 'COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER', true) AS issuer,
    set_config('comuni.operator_subject',
               secret ->> 'COMUNI_PLATFORM_OPERATOR_SUBJECT', true) AS subject,
    set_config('comuni.operator_action',
               secret ->> 'COMUNI_PLATFORM_OPERATOR_ACTION', true) AS action,
    set_config('comuni.operator_ticket',
               secret ->> 'COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET', true) AS ticket,
    set_config('comuni.operator_approver',
               secret ->> 'COMUNI_PLATFORM_OPERATOR_APPROVER', true) AS approver
FROM private_json
\gset

DO $operator$
DECLARE
    v_issuer text := current_setting('comuni.operator_issuer', true);
    v_subject text := current_setting('comuni.operator_subject', true);
    v_action text := current_setting('comuni.operator_action', true);
    v_ticket text := current_setting('comuni.operator_ticket', true);
    v_approver text := current_setting('comuni.operator_approver', true);
    v_id uuid;
    v_active boolean;
    v_event text;
BEGIN
    -- Runtime cannot grant/revoke platform permissions even with signed RLS
    -- tenant context. Owners of BOTH tables are the only supported operators.
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.platform_operators'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.platform_operator_audit_events'::regclass
    ) THEN
        RAISE EXCEPTION 'Platform operator management requires schema owner';
    END IF;

    -- Conservative HTTPS issuer syntax, exact OIDC subject; validate issuer
    -- and sub against a trusted IdP before running. This checks syntax ONLY.
    IF v_issuer IS NULL OR length(v_issuer) > 512 OR v_issuer !~
        '^https://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(/[-A-Za-z0-9._~/%]*)?$' THEN
        RAISE EXCEPTION 'Invalid HTTPS issuer input';
    END IF;
    IF v_subject IS NULL OR length(v_subject) NOT BETWEEN 1 AND 160
        OR v_subject <> btrim(v_subject) OR v_subject ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'Invalid exact OIDC subject input';
    END IF;
    IF v_action IS NULL OR v_action NOT IN ('enroll', 'revoke') THEN
        RAISE EXCEPTION 'Invalid platform operator action';
    END IF;
    IF v_ticket IS NULL OR v_ticket !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{7,109}$'
        OR v_approver IS NULL OR v_approver !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' THEN
        RAISE EXCEPTION 'Missing or invalid independent approval reference';
    END IF;

    -- The first enrollment has no row to lock. Serialize new and existing
    -- requests for the SAME issuer+sub, then row-lock an existing identity.
    PERFORM pg_advisory_xact_lock(
        hashtextextended(v_issuer || chr(31) || v_subject, 0));

    SELECT operator_id, is_active INTO v_id, v_active
    FROM platform.platform_operators
    WHERE identity_issuer = v_issuer AND subject = v_subject
    FOR UPDATE;

    IF NOT FOUND THEN
        IF v_action <> 'enroll' THEN
            RAISE EXCEPTION 'Unknown platform operator: revocation refused';
        END IF;

        INSERT INTO platform.platform_operators(identity_issuer, subject, is_active)
        VALUES (v_issuer, v_subject, TRUE)
        RETURNING operator_id INTO v_id;
        v_event := 'platform.operator.enrolled';
    ELSIF v_active = (v_action = 'enroll') THEN
        -- Same target state is an idempotent, non-audited retry.
        RETURN;
    ELSE
        -- A distinct change approval is required for each actual
        -- transition. Replaying the same ticket cannot undo a revocation.
        IF EXISTS (
            SELECT 1 FROM platform.platform_operator_audit_events
            WHERE resource_id = v_id AND correlation_id = 'operator:' || v_ticket
        ) THEN
            RAISE EXCEPTION 'Change ticket already used for operator transition';
        END IF;

        UPDATE platform.platform_operators
        SET is_active = (v_action = 'enroll')
        WHERE identity_issuer = v_issuer AND subject = v_subject;

        v_event := CASE WHEN v_action = 'enroll'
            THEN 'platform.operator.reactivated'
            ELSE 'platform.operator.revoked' END;
    END IF;

    -- Single commit: actor, action, stable random resource id and ticket.
    -- Never store issuer, subject, reviewer or personal information in audit.
    INSERT INTO platform.platform_operator_audit_events(
        id, actor_subject, action, resource_type, resource_id,
        correlation_id, occurred_at
    ) VALUES (
        gen_random_uuid(), 'db-owner:' || current_user, v_event,
        'platform.operator', v_id, 'operator:' || v_ticket, now()
    );
END
$operator$;

COMMIT;

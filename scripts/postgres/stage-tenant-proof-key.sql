\set ON_ERROR_STOP on

-- Versioned tenant proof key staging (ADR 0074 / #90).
-- Owner-only offline, private runner, trusted checkout, working directory
-- at repository root, Python3. No SQL literal with signing key or key ID.
-- All statements and row locks are inside one transaction. Base64 is NOT
-- encryption; neither shell tracing nor client COPY output logging is allowed.
BEGIN;

-- Signing keys can appear in pgAudit FUNCTION/WRITE bind-value fields even
-- with private client-side COPY. Reject parameter-value logging before the
-- producer runs, but keep ROLE/DDL/WRITE/FUNCTION metadata and SQL statements.
DO $owner_audit_parameter_guard$
BEGIN
    IF lower(coalesce(current_setting('pgaudit.log_parameter', true), 'off')) = 'on' THEN
        RAISE EXCEPTION 'Owner-only signing key operation requires parameter-free audit metadata';
    END IF;
END
$owner_audit_parameter_guard$;

SET LOCAL lock_timeout = '10s';

CREATE TEMP TABLE pg_temp.comuni_private_input (payload text NOT NULL)
ON COMMIT DROP;
\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py tenant-stage' WITH (FORMAT csv)

DO $tenant_stage$
DECLARE
    v_payload jsonb;
    v_key_id text;
    v_key text;
BEGIN
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.tenant_proof_keys'::regclass
    ) THEN
        RAISE EXCEPTION 'Versioned tenant proof staging requires schema owner';
    END IF;

    IF (SELECT count(*) FROM pg_temp.comuni_private_input) <> 1 THEN
        RAISE EXCEPTION 'Invalid private signing key input envelope';
    END IF;
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb
    INTO v_payload FROM pg_temp.comuni_private_input;
    v_key_id := v_payload ->> 'TENANT_PROOF_KEY_ID';
    v_key := v_payload ->> 'TENANT_PROOF_KEY';

    IF v_key_id IS NULL OR v_key_id !~ '^[a-z][a-z0-9_-]{0,31}$'
       OR v_key_id = 'legacy'
       OR v_key IS NULL OR octet_length(v_key) < 32 THEN
        RAISE EXCEPTION 'Invalid staged key identifier or signing key';
    END IF;

    -- Coordinates staging with owner-only retire-tenant-proof-key.sql.
    -- SHARE ROW EXCLUSIVE serializes two concurrent stage/retire changes
    -- without blocking the RLS proof verifier's ordinary SELECT.
    LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;
    INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
    VALUES (v_key_id, v_key)
    ON CONFLICT (key_id) DO NOTHING;

    IF NOT EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = v_key_id AND signing_key = v_key
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'Key ID already has different material, expired or revoked';
    END IF;
END
$tenant_stage$;

COMMIT;

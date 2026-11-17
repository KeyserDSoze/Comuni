\set ON_ERROR_STOP on

-- Legacy tenant proof bootstrap (not rotation): only the schema/migration
-- owner, on a trusted private PostgreSQL runner after EF migrations.
-- ADR 0074 / #90. Base64 is transport, NOT encryption. Never echo COPY data.
-- Run from the repository root with Python3 and trusted checkout.
BEGIN;

-- Fixed client-side \copy streams the allowlisted signing key via COPY STDIN;
-- it is never interpolated into the SQL statement text (unlike :'var').
CREATE TEMP TABLE pg_temp.comuni_private_input (payload text NOT NULL)
ON COMMIT DROP;
\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py tenant-legacy' WITH (FORMAT csv)

DO $tenant_legacy$
DECLARE
    v_payload jsonb;
    v_key text;
BEGIN
    IF current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.tenant_proof_secret'::regclass
    ) OR current_user <> (
        SELECT pg_get_userbyid(relowner)
        FROM pg_class WHERE oid = 'platform.tenant_proof_keys'::regclass
    ) THEN
        RAISE EXCEPTION 'Tenant proof provisioning requires schema owner';
    END IF;

    IF (SELECT count(*) FROM pg_temp.comuni_private_input) <> 1 THEN
        RAISE EXCEPTION 'Invalid private tenant proof input envelope';
    END IF;
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb
    INTO v_payload FROM pg_temp.comuni_private_input;
    v_key := v_payload ->> 'TENANT_PROOF_KEY';
    IF v_key IS NULL OR octet_length(v_key) < 32 THEN
        RAISE EXCEPTION 'Tenant proof signing key must contain at least 32 bytes';
    END IF;

    -- Fail-closed and idempotent: cannot overwrite or resurrect retired keys.
    INSERT INTO platform.tenant_proof_secret (id, signing_key)
    VALUES (1, v_key)
    ON CONFLICT (id) DO NOTHING;
    INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
    VALUES ('legacy', v_key)
    ON CONFLICT (key_id) DO NOTHING;

    IF NOT EXISTS (
        SELECT 1 FROM platform.tenant_proof_secret
        WHERE id = 1 AND signing_key = v_key
    ) OR NOT EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = 'legacy' AND signing_key = v_key
          AND revoked_at IS NULL AND valid_until > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'Legacy key mismatch or retirement; use versioned staging';
    END IF;
END
$tenant_legacy$;

COMMIT;

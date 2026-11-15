\set ON_ERROR_STOP on

-- Versioned tenant key staging: run ONLY with schema-owner credentials in the private VNet.
-- Keys are read from environment and never echoed. Repeating with a different secret
-- or a revoked/expired ID fails; use a fresh ID for every rotation.
\getenv new_key_id TENANT_PROOF_KEY_ID
\getenv new_key TENANT_PROOF_KEY
\if :{?new_key_id}
\else
    \echo 'TENANT_PROOF_KEY_ID missing.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif
\if :{?new_key}
\else
    \echo 'TENANT_PROOF_KEY missing.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

SELECT CASE WHEN :'new_key_id' ~ '^[a-z][a-z0-9_-]{0,31}$'
          AND octet_length(:'new_key') >= 32
          AND :'new_key_id' <> 'legacy'
       THEN 'true' ELSE 'false' END AS valid \gset
\if :valid
\else
    \echo 'Invalid staged key ID or secret length.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

BEGIN;
INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
VALUES (:'new_key_id', :'new_key')
ON CONFLICT (key_id) DO NOTHING;

SELECT CASE WHEN EXISTS (
    SELECT 1 FROM platform.tenant_proof_keys
    WHERE key_id = :'new_key_id' AND signing_key = :'new_key'
      AND revoked_at IS NULL
      AND not_before <= clock_timestamp() AND valid_until > clock_timestamp()
) THEN 'true' ELSE 'false' END AS verified \gset
\if :verified
    COMMIT;
\else
    ROLLBACK;
    \echo 'Key ID already exists with different material, has expired, or was revoked.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

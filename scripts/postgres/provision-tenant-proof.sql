\set ON_ERROR_STOP on

-- Initial bootstrap of the legacy verifier; never use this as a key rotation command.
-- Run as schema owner. The key comes from the runner environment, not command arguments.
\getenv tenant_proof_key TENANT_PROOF_KEY
\if :{?tenant_proof_key}
\else
    \echo 'TENANT_PROOF_KEY missing; refusing to provision.'
    \quit 3
\endif

SELECT CASE WHEN octet_length(:'tenant_proof_key') >= 32 THEN 'true' ELSE 'false' END AS valid \gset
\if :valid
\else
    \echo 'TENANT_PROOF_KEY must contain at least 32 bytes.'
    \quit 3
\endif

BEGIN;
INSERT INTO platform.tenant_proof_secret (id, signing_key)
VALUES (1, :'tenant_proof_key')
ON CONFLICT (id) DO NOTHING;
INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
VALUES ('legacy', :'tenant_proof_key')
ON CONFLICT (key_id) DO NOTHING;

-- Never overwrite or reactivate existing key material silently.
SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_secret
            WHERE id = 1 AND signing_key = :'tenant_proof_key')
    AND EXISTS (SELECT 1 FROM platform.tenant_proof_keys
                WHERE key_id = 'legacy' AND signing_key = :'tenant_proof_key'
                AND revoked_at IS NULL AND valid_until > clock_timestamp())
    THEN 'true' ELSE 'false' END AS verified \gset
\if :verified
    COMMIT;
\else
    ROLLBACK;
    \echo 'Legacy key mismatch or retirement; use the versioned staging procedure.'
    \quit 3
\endif

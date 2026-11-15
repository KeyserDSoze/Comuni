\set ON_ERROR_STOP on

-- Reduce the acceptance window for a prior key; cannot extend it or un-revoke.
-- 0 seconds revokes immediately. Non-zero grace should cover old proof TTL (3 min)
-- and the verified rolling deploy; operator must assess active replicas first.
\getenv retire_id TENANT_PROOF_RETIRE_KEY_ID
\getenv grace_secs TENANT_PROOF_GRACE_SECONDS
\if :{?retire_id}
\else
    \echo 'TENANT_PROOF_RETIRE_KEY_ID missing.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif
\if :{?grace_secs}
\else
    \echo 'TENANT_PROOF_GRACE_SECONDS missing.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

SELECT CASE WHEN :'retire_id' ~ '^[a-z][a-z0-9_-]{0,31}$'
          AND :'grace_secs' ~ '^[0-9]{1,4}$'
          AND (:'grace_secs')::integer BETWEEN 0 AND 3600
       THEN 'true' ELSE 'false' END AS valid \gset
\if :valid
\else
    \echo 'Invalid key ID or grace seconds (0..3600).'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

BEGIN;
UPDATE platform.tenant_proof_keys
SET valid_until = least(valid_until,
                        clock_timestamp() + (:'grace_secs')::integer * interval '1 second'),
    revoked_at = CASE WHEN (:'grace_secs')::integer = 0
        THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
WHERE key_id = :'retire_id';

SELECT CASE WHEN EXISTS (
    SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = :'retire_id'
) THEN 'true' ELSE 'false' END AS verified \gset
\if :verified
    COMMIT;
\else
    ROLLBACK;
    \echo 'Unknown key ID; no changes applied.'
    DO $ BEGIN RAISE EXCEPTION 'Provisioning refused by safety guard'; END $;
\endif

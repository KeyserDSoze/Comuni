\set ON_ERROR_STOP on

-- Owner-only retirement guard (ADR 0040/#46). No signing key is needed.
-- A replacement ID MUST already exist, be active, and outlive grace + the
-- maximum accepted proof horizon (300 seconds). This is not an Azure rollout
-- verifier or authorization to retire keys before replicas are drained.
\getenv retire_id TENANT_PROOF_RETIRE_KEY_ID
\getenv replacement_id TENANT_PROOF_REPLACEMENT_KEY_ID
\getenv grace_secs TENANT_PROOF_GRACE_SECONDS
\if :{?retire_id}
\else
    \echo 'TENANT_PROOF_RETIRE_KEY_ID missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif
\if :{?replacement_id}
\else
    \echo 'TENANT_PROOF_REPLACEMENT_KEY_ID missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif
\if :{?grace_secs}
\else
    \echo 'TENANT_PROOF_GRACE_SECONDS missing.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

-- Only ID metadata and integer grace are accepted; never print these values.
SELECT CASE WHEN :'retire_id' ~ '^[a-z][a-z0-9_-]{0,31}$'
          AND :'replacement_id' ~ '^[a-z][a-z0-9_-]{0,31}$'
          AND :'retire_id' <> :'replacement_id'
          AND :'grace_secs' ~ '^[0-9]{1,4}$'
          AND (:'grace_secs')::integer BETWEEN 0 AND 3600
       THEN 'true' ELSE 'false' END AS valid \gset
\if :valid
\else
    \echo 'Invalid key IDs or grace seconds (0..3600).'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '10s';
-- Serializes successive or reciprocal retirements and concurrent staging.
-- Does not block ordinary SELECT by the volatile RLS verifier.
LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;

SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = :'retire_id')
    AND EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = :'replacement_id'
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
              + (:'grace_secs')::integer * interval '1 second'
              + interval '300 seconds'
    ) THEN 'true' ELSE 'false' END AS replacement_safe \gset

\if :replacement_safe
    -- A retry may shorten, but can NEVER lengthen the acceptance window or
    -- clear an already committed revocation timestamp.
    UPDATE platform.tenant_proof_keys
    SET valid_until = least(valid_until,
                            clock_timestamp() + (:'grace_secs')::integer * interval '1 second'),
        revoked_at = CASE WHEN (:'grace_secs')::integer = 0
            THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
    WHERE key_id = :'retire_id';
    COMMIT;
\else
    ROLLBACK;
    \echo 'No safe active replacement; retirement blocked.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

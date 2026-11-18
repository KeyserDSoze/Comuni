\set ON_ERROR_STOP on

-- Owner-only retirement guard (ADR 0040/#46, private transport #103).
-- A separately approved operator must verify all replicas and the successor.
-- These inputs are non-secret key identifiers and grace metadata, but SQL
-- statement logging may disclose them unless transported outside literals.
-- Never use -a/-e, shell tracing, public logs or runtime credentials.
-- Run from the trusted repository root for the fixed client-side COPY helper.
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

BEGIN;

-- COPY runs on the psql CLIENT, not the PostgreSQL server. Only the three
-- allowlisted fields are streamed as one base64(JSON) row (not encryption).
-- A failed input/validation exits ON_ERROR_STOP and rolls the whole tx back.
CREATE TEMP TABLE pg_temp.comuni_private_input (
    payload text NOT NULL
) ON COMMIT DROP;

\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py retire-tenant-proof' WITH (FORMAT csv)

WITH private_json AS (
    SELECT convert_from(decode(payload, 'base64'), 'UTF8')::jsonb AS secret
    FROM pg_temp.comuni_private_input
)
SELECT
    set_config('comuni.retire_id',
               secret ->> 'TENANT_PROOF_RETIRE_KEY_ID', true) AS retire_id,
    set_config('comuni.replacement_id',
               secret ->> 'TENANT_PROOF_REPLACEMENT_KEY_ID', true) AS replacement_id,
    set_config('comuni.grace_secs',
               secret ->> 'TENANT_PROOF_GRACE_SECONDS', true) AS grace_secs
FROM private_json
\gset

-- Preserve the existing strict metadata validation without SQL literals.
-- Guard the cast with a nested CASE: boolean AND is not guaranteed to
-- short-circuit, and a cast error could echo invalid private input in logs.
SELECT CASE
         WHEN current_setting('comuni.retire_id', true) ~ '^[a-z][a-z0-9_-]{0,31}
\if :valid
\else
    \echo 'Invalid key IDs or grace seconds (0..3600).'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

SET LOCAL lock_timeout = '10s';
-- Serializes successive or reciprocal retirements and concurrent staging.
-- Does not block ordinary SELECT by the volatile RLS verifier.
LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;

SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = current_setting('comuni.retire_id', true))
    AND EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = current_setting('comuni.replacement_id', true)
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
              + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'
              + interval '300 seconds'
    ) THEN 'true' ELSE 'false' END AS replacement_safe \gset

\if :replacement_safe
    -- A retry may shorten, but can NEVER lengthen the acceptance window or
    -- clear an already committed revocation timestamp.
    UPDATE platform.tenant_proof_keys
    SET valid_until = least(valid_until,
                            clock_timestamp() + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'),
        revoked_at = CASE WHEN (current_setting('comuni.grace_secs', true))::integer = 0
            THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
    WHERE key_id = current_setting('comuni.retire_id', true);
    COMMIT;
\else
    ROLLBACK;
    \echo 'No safe active replacement; retirement blocked.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

          AND current_setting('comuni.replacement_id', true) ~ '^[a-z][a-z0-9_-]{0,31}
\if :valid
\else
    \echo 'Invalid key IDs or grace seconds (0..3600).'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

SET LOCAL lock_timeout = '10s';
-- Serializes successive or reciprocal retirements and concurrent staging.
-- Does not block ordinary SELECT by the volatile RLS verifier.
LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;

SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = current_setting('comuni.retire_id', true))
    AND EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = current_setting('comuni.replacement_id', true)
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
              + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'
              + interval '300 seconds'
    ) THEN 'true' ELSE 'false' END AS replacement_safe \gset

\if :replacement_safe
    -- A retry may shorten, but can NEVER lengthen the acceptance window or
    -- clear an already committed revocation timestamp.
    UPDATE platform.tenant_proof_keys
    SET valid_until = least(valid_until,
                            clock_timestamp() + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'),
        revoked_at = CASE WHEN (current_setting('comuni.grace_secs', true))::integer = 0
            THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
    WHERE key_id = current_setting('comuni.retire_id', true);
    COMMIT;
\else
    ROLLBACK;
    \echo 'No safe active replacement; retirement blocked.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

          AND current_setting('comuni.retire_id', true) <> current_setting('comuni.replacement_id', true)
          AND current_setting('comuni.grace_secs', true) ~ '^[0-9]{1,4}
\if :valid
\else
    \echo 'Invalid key IDs or grace seconds (0..3600).'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

SET LOCAL lock_timeout = '10s';
-- Serializes successive or reciprocal retirements and concurrent staging.
-- Does not block ordinary SELECT by the volatile RLS verifier.
LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;

SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = current_setting('comuni.retire_id', true))
    AND EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = current_setting('comuni.replacement_id', true)
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
              + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'
              + interval '300 seconds'
    ) THEN 'true' ELSE 'false' END AS replacement_safe \gset

\if :replacement_safe
    -- A retry may shorten, but can NEVER lengthen the acceptance window or
    -- clear an already committed revocation timestamp.
    UPDATE platform.tenant_proof_keys
    SET valid_until = least(valid_until,
                            clock_timestamp() + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'),
        revoked_at = CASE WHEN (current_setting('comuni.grace_secs', true))::integer = 0
            THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
    WHERE key_id = current_setting('comuni.retire_id', true);
    COMMIT;
\else
    ROLLBACK;
    \echo 'No safe active replacement; retirement blocked.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

         THEN CASE WHEN current_setting('comuni.grace_secs', true)::integer BETWEEN 0 AND 3600
              THEN 'true' ELSE 'false' END
         ELSE 'false'
       END AS valid \gset
\if :valid
\else
    \echo 'Invalid key IDs or grace seconds (0..3600).'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

SET LOCAL lock_timeout = '10s';
-- Serializes successive or reciprocal retirements and concurrent staging.
-- Does not block ordinary SELECT by the volatile RLS verifier.
LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE;

SELECT CASE WHEN
    EXISTS (SELECT 1 FROM platform.tenant_proof_keys WHERE key_id = current_setting('comuni.retire_id', true))
    AND EXISTS (
        SELECT 1 FROM platform.tenant_proof_keys
        WHERE key_id = current_setting('comuni.replacement_id', true)
          AND revoked_at IS NULL
          AND not_before <= clock_timestamp()
          AND valid_until > clock_timestamp()
              + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'
              + interval '300 seconds'
    ) THEN 'true' ELSE 'false' END AS replacement_safe \gset

\if :replacement_safe
    -- A retry may shorten, but can NEVER lengthen the acceptance window or
    -- clear an already committed revocation timestamp.
    UPDATE platform.tenant_proof_keys
    SET valid_until = least(valid_until,
                            clock_timestamp() + (current_setting('comuni.grace_secs', true))::integer * interval '1 second'),
        revoked_at = CASE WHEN (current_setting('comuni.grace_secs', true))::integer = 0
            THEN coalesce(revoked_at, clock_timestamp()) ELSE revoked_at END
    WHERE key_id = current_setting('comuni.retire_id', true);
    COMMIT;
\else
    ROLLBACK;
    \echo 'No safe active replacement; retirement blocked.'
    DO $$ BEGIN RAISE EXCEPTION 'Retirement refused by safety guard'; END $$;
\endif

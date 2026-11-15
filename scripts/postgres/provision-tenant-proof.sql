\set ON_ERROR_STOP on

-- Run by the PostgreSQL schema owner after EF migrations and before API rollout.
-- TENANT_PROOF_KEY must match Security__TenantProofKey in the API runtime.
\getenv tenant_proof_key TENANT_PROOF_KEY
\if :{?tenant_proof_key}
\else
    \echo 'TENANT_PROOF_KEY missing; tenant verifier provisioning aborted.'
    \quit 3
\endif

-- Quoted psql variable performs SQL-literal escaping and is not echoed by -f.
INSERT INTO platform.tenant_proof_secret (id, signing_key)
VALUES (1, :'tenant_proof_key')
ON CONFLICT (id) DO UPDATE SET signing_key = EXCLUDED.signing_key;

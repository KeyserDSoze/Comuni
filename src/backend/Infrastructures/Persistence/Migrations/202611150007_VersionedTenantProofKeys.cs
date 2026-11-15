using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150007_VersionedTenantProofKeys")]
public sealed class VersionedTenantProofKeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- Only the migration owner can stage or retire verification material.
            -- Neither this table nor any signing function is granted to the runtime login.
            CREATE TABLE platform.tenant_proof_keys (
                key_id varchar(32) PRIMARY KEY
                    CHECK (key_id ~ '^[a-z][a-z0-9_-]{0,31}$'),
                signing_key text NOT NULL CHECK (octet_length(signing_key) >= 32),
                not_before timestamptz NOT NULL DEFAULT '-infinity',
                valid_until timestamptz NOT NULL DEFAULT 'infinity',
                revoked_at timestamptz,
                CONSTRAINT ck_tenant_proof_keys_window CHECK (valid_until > not_before)
            );
            REVOKE ALL ON platform.tenant_proof_keys FROM PUBLIC;

            -- Preserve proofs from API replicas running the previous four-field signer
            -- during an owner-controlled migration grace period.
            INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
            SELECT 'legacy', signing_key
            FROM platform.tenant_proof_secret WHERE id = 1;

            CREATE OR REPLACE FUNCTION platform.verified_tenant_id() RETURNS uuid
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $$
            DECLARE
                assertion text := current_setting('comuni.tenant_assertion', true);
                parts text[];
                v_key_id text;
                v_tenant text;
                v_expiry bigint;
                v_nonce text;
                v_mac text;
                v_message text;
                v_secret text;
                v_expected_mac text;
                v_now timestamptz := clock_timestamp();
                v_epoch bigint;
            BEGIN
                IF assertion IS NULL OR length(assertion) > 320 THEN
                    RETURN NULL;
                END IF;

                parts := string_to_array(assertion, '|');
                IF assertion ~ '^[a-z][a-z0-9_-]{0,31}[|][0-9a-f]{32}[|][0-9]{10,12}[|][0-9a-f]{32}[|][0-9a-f]{64}$' THEN
                    v_key_id := parts[1];
                    v_tenant := parts[2];
                    v_expiry := parts[3]::bigint;
                    v_nonce := parts[4];
                    v_mac := parts[5];
                    v_message := v_key_id || '|' || v_tenant || '|' ||
                                 parts[3] || '|' || v_nonce;
                ELSIF assertion ~ '^[0-9a-f]{32}[|][0-9]{10,12}[|][0-9a-f]{32}[|][0-9a-f]{64}$' THEN
                    v_key_id := 'legacy';
                    v_tenant := parts[1];
                    v_expiry := parts[2]::bigint;
                    v_nonce := parts[3];
                    v_mac := parts[4];
                    v_message := v_tenant || '|' || parts[2] || '|' || v_nonce;
                ELSE
                    RETURN NULL;
                END IF;

                v_epoch := floor(extract(epoch FROM v_now))::bigint;
                IF v_expiry <= v_epoch OR v_expiry > v_epoch + 300 THEN
                    RETURN NULL;
                END IF;

                SELECT k.signing_key INTO v_secret
                FROM platform.tenant_proof_keys AS k
                WHERE k.key_id = v_key_id AND k.revoked_at IS NULL
                  AND k.not_before <= v_now AND k.valid_until > v_now;
                IF v_secret IS NULL THEN
                    RETURN NULL;
                END IF;

                v_expected_mac := encode(public.hmac(v_message, v_secret, 'sha256'), 'hex');
                IF v_expected_mac <> v_mac THEN
                    RETURN NULL;
                END IF;
                RETURN v_tenant::uuid;
            END
            $$;

            -- Replacing a function retains its existing privileges; enforce the explicit grant.
            REVOKE ALL ON FUNCTION platform.verified_tenant_id() FROM PUBLIC;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException(
            "Downgrading signed tenant key verification can reactivate revoked keys. Rollback requires a separately reviewed migration.");
}

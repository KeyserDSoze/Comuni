using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150006_SignedTenantRlsProof")]
public sealed class SignedTenantRlsProof : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

            -- Intentionally not tenant-owned: only the migration owner can read or rotate
            -- this material. The runtime login has no SELECT/UPDATE/INSERT grants here.
            CREATE TABLE platform.tenant_proof_secret (
                id integer PRIMARY KEY CHECK (id = 1),
                signing_key text NOT NULL CHECK (octet_length(signing_key) >= 32)
            );

            -- No token-signing routine is exposed to the runtime role.
            -- Only a verification function may read the DB-side secret.
            CREATE FUNCTION platform.verified_tenant_id() RETURNS uuid
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $$
            DECLARE
                assertion text := current_setting('comuni.tenant_assertion', true);
                parts text[];
                key text;
                expected_mac text;
                expiration bigint;
                current_epoch bigint;
            BEGIN
                IF assertion IS NULL OR length(assertion) > 256 OR
                   assertion !~ '^[0-9a-f]{32}[|][0-9]{10,12}[|][0-9a-f]{32}[|][0-9a-f]{64}$'
                THEN
                    RETURN NULL;
                END IF;

                parts := string_to_array(assertion, '|');
                expiration := parts[2]::bigint;
                current_epoch := floor(extract(epoch FROM clock_timestamp()))::bigint;
                IF expiration <= current_epoch OR expiration > current_epoch + 300 THEN
                    RETURN NULL;
                END IF;

                SELECT signing_key INTO key FROM platform.tenant_proof_secret WHERE id = 1;
                IF key IS NULL THEN
                    RETURN NULL;
                END IF;

                expected_mac := encode(public.hmac(
                    parts[1] || '|' || parts[2] || '|' || parts[3],
                    key, 'sha256'), 'hex');

                IF expected_mac <> parts[4] THEN
                    RETURN NULL;
                END IF;

                RETURN parts[1]::uuid;
            END
            $$;

            -- PostgreSQL grants EXECUTE on new functions to PUBLIC by default.
            -- Grant the verifier explicitly to the restricted role *after* migrations.
            REVOKE ALL ON FUNCTION platform.verified_tenant_id() FROM PUBLIC;

            ALTER POLICY comuni_tenant_isolation ON platform.organizations
                USING (id = platform.verified_tenant_id())
                WITH CHECK (id = platform.verified_tenant_id());

            ALTER POLICY comuni_tenant_isolation ON platform.organization_modules
                USING (organization_id = platform.verified_tenant_id())
                WITH CHECK (organization_id = platform.verified_tenant_id());

            ALTER POLICY comuni_tenant_isolation ON platform.organization_memberships
                USING (organization_id = platform.verified_tenant_id())
                WITH CHECK (organization_id = platform.verified_tenant_id());

            ALTER POLICY comuni_tenant_isolation ON protocol.records
                USING (organization_id = platform.verified_tenant_id())
                WITH CHECK (organization_id = platform.verified_tenant_id());

            ALTER POLICY comuni_tenant_isolation ON platform.audit_events
                USING (organization_id = platform.verified_tenant_id())
                WITH CHECK (organization_id = platform.verified_tenant_id());
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            ALTER POLICY comuni_tenant_isolation ON platform.organizations
                USING (id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            ALTER POLICY comuni_tenant_isolation ON platform.organization_modules
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            ALTER POLICY comuni_tenant_isolation ON platform.organization_memberships
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            ALTER POLICY comuni_tenant_isolation ON protocol.records
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            ALTER POLICY comuni_tenant_isolation ON platform.audit_events
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            DROP FUNCTION platform.verified_tenant_id();
            DROP TABLE platform.tenant_proof_secret;
            """);
    }
}

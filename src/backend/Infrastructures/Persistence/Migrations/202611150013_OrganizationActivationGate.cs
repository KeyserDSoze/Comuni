using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

/// <summary>
/// Add a fail-closed activation gate without changing the meaning of legacy
/// suspension flags or unexpectedly disabling existing organizations.
/// </summary>
[DbContext(typeof(ComuniDbContext))]
[Migration("202611150013_OrganizationActivationGate")]
public sealed class OrganizationActivationGate : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- Existing active AND suspended municipalities are already provisioned:
            -- default TRUE prevents accidental production-wide service denial.
            ALTER TABLE platform.organizations
                ADD COLUMN is_activated boolean NOT NULL DEFAULT TRUE;
            ALTER TABLE platform.organizations
                ADD CONSTRAINT ck_organizations_suspended_requires_activation
                    CHECK (is_activated OR NOT is_suspended);

            -- Existing inventory consumers still receive four columns. Its
            -- is_suspended compatibility flag now means NON-OPERATIONAL: a
            -- pending municipality MUST NOT be displayed as operational.
            -- CREATE OR REPLACE retains existing view grants and ownership.
            CREATE OR REPLACE VIEW platform.platform_organization_inventory
                WITH (security_barrier = true)
            AS
                SELECT o.id, o.name,
                       (o.is_suspended OR NOT o.is_activated) AS is_suspended,
                       COALESCE(m.enabled, FALSE) AS protocol_enabled
                FROM platform.organizations AS o
                LEFT JOIN platform.organization_modules AS m
                    ON m.organization_id = o.id AND m.module_key = 'protocol';
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- Refuse a schema downgrade that would implicitly activate any
            -- pending tenant by removing the new authorization gate.
            DO $downgrade$
            BEGIN
                IF EXISTS (SELECT 1 FROM platform.organizations WHERE is_activated = FALSE) THEN
                    RAISE EXCEPTION 'Cannot remove activation gate while pending organizations exist';
                END IF;
            END
            $downgrade$;

            CREATE OR REPLACE VIEW platform.platform_organization_inventory
                WITH (security_barrier = true)
            AS
                SELECT o.id, o.name, o.is_suspended,
                       COALESCE(m.enabled, FALSE) AS protocol_enabled
                FROM platform.organizations AS o
                LEFT JOIN platform.organization_modules AS m
                    ON m.organization_id = o.id AND m.module_key = 'protocol';

            ALTER TABLE platform.organizations
                DROP CONSTRAINT ck_organizations_suspended_requires_activation;
            ALTER TABLE platform.organizations DROP COLUMN is_activated;
            """);
    }
}

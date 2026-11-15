using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

/// <summary>
/// Deliberately non-invokable by the municipal SQL principal. The inventory
/// view runs under owner rights and is granted to a separate, restricted role.
/// </summary>
[DbContext(typeof(ComuniDbContext))]
[Migration("202611150012_PlatformOrganizationInventory")]
public sealed class PlatformOrganizationInventory : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            CREATE VIEW platform.platform_organization_inventory
              WITH (security_barrier = true)
            AS
            SELECT o.id, o.name, o.is_suspended,
                   COALESCE(m.enabled, FALSE) AS protocol_enabled
            FROM platform.organizations AS o
            LEFT JOIN platform.organization_modules AS m
                ON m.organization_id = o.id AND m.module_key = 'protocol';

            REVOKE ALL ON TABLE platform.platform_organization_inventory
                FROM PUBLIC;

            -- SQL principal used only for the platform inventory can resolve
            -- the verified operator's pseudonymous stable audit identifier.
            -- This function is NOT granted to comuni_app_runtime.
            CREATE FUNCTION platform.active_platform_operator_id(
                candidate_issuer text, candidate_subject text)
            RETURNS uuid
            LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path = pg_catalog, platform
            AS $inventory_actor$
                SELECT operator_id
                FROM platform.platform_operators
                WHERE identity_issuer = candidate_issuer
                  AND subject = candidate_subject
                  AND is_active = TRUE
            $inventory_actor$;
            REVOKE ALL ON FUNCTION
                platform.active_platform_operator_id(text,text) FROM PUBLIC;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DROP FUNCTION IF EXISTS platform.active_platform_operator_id(text,text);
            DROP VIEW IF EXISTS platform.platform_organization_inventory;
            """);
    }
}

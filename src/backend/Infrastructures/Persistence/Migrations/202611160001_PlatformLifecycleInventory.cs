using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

/// <summary>
/// Append a derived lifecycle field to the restricted global inventory.
/// </summary>
[DbContext(typeof(ComuniDbContext))]
[Migration("202611160001_PlatformLifecycleInventory")]
public sealed class PlatformLifecycleInventory : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- Preserve existing four view columns, order, grants and owner.
            CREATE OR REPLACE VIEW platform.platform_organization_inventory
                WITH (security_barrier = true)
            AS
                SELECT o.id, o.name,
                       (o.is_suspended OR NOT o.is_activated) AS is_suspended,
                       COALESCE(m.enabled, FALSE) AS protocol_enabled,
                       CASE
                           WHEN NOT o.is_activated THEN 'created'
                           WHEN o.is_suspended THEN 'suspended'
                           ELSE 'active'
                       END AS lifecycle_status
                FROM platform.organizations AS o
                LEFT JOIN platform.organization_modules AS m
                    ON m.organization_id = o.id AND m.module_key = 'protocol';
            REVOKE ALL ON TABLE platform.platform_organization_inventory FROM PUBLIC;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- RESTRICT refuses dependent objects; transactional rollback
            -- prevents any gap in the owner's security-barrier view.
            DROP VIEW platform.platform_organization_inventory RESTRICT;
            CREATE VIEW platform.platform_organization_inventory
                WITH (security_barrier = true)
            AS
                SELECT o.id, o.name,
                       (o.is_suspended OR NOT o.is_activated) AS is_suspended,
                       COALESCE(m.enabled, FALSE) AS protocol_enabled
                FROM platform.organizations AS o
                LEFT JOIN platform.organization_modules AS m
                    ON m.organization_id = o.id AND m.module_key = 'protocol';
            REVOKE ALL ON TABLE platform.platform_organization_inventory FROM PUBLIC;
            DO $inventory_rollback$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'comuni_platform_reader') THEN
                    EXECUTE 'GRANT SELECT ON TABLE platform.platform_organization_inventory TO comuni_platform_reader';
                END IF;
            END $inventory_rollback$;
            """);
    }
}

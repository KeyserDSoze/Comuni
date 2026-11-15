using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150008_RuntimeMembershipRoleGuard")]
public sealed class RuntimeMembershipRoleGuard : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Existing tenant policy is PERMISSIVE FOR ALL. These RESTRICTIVE policies
        // are ANDed with it. Runtime must not gain Admin via direct SQL or injection.
        // Refer to a current_user string (the role may not exist during owner migration).
        migrationBuilder.Sql("""
            CREATE POLICY comuni_membership_runtime_insert_guard
                ON platform.organization_memberships
                AS RESTRICTIVE FOR INSERT TO PUBLIC
                WITH CHECK (current_user <> 'comuni_app_runtime'
                            OR role IN ('Reader', 'Officer'));

            CREATE POLICY comuni_membership_runtime_update_guard
                ON platform.organization_memberships
                AS RESTRICTIVE FOR UPDATE TO PUBLIC
                USING (current_user <> 'comuni_app_runtime'
                       OR role IN ('Reader', 'Officer'))
                WITH CHECK (current_user <> 'comuni_app_runtime'
                            OR role IN ('Reader', 'Officer'));
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DROP POLICY IF EXISTS comuni_membership_runtime_update_guard
                ON platform.organization_memberships;
            DROP POLICY IF EXISTS comuni_membership_runtime_insert_guard
                ON platform.organization_memberships;
            """);
    }
}

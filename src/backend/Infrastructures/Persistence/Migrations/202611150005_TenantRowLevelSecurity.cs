using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150005_TenantRowLevelSecurity")]
public sealed class TenantRowLevelSecurity : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Schema owners and superusers bypass these policies. The production API MUST
        // connect with the distinct, non-owner login comuni_app_runtime (ADR 0011).
        // Fail closed when no transaction-local organization has been set.
        migrationBuilder.Sql("""
            ALTER TABLE platform.organizations ENABLE ROW LEVEL SECURITY;
            CREATE POLICY comuni_tenant_isolation ON platform.organizations
                FOR ALL TO PUBLIC
                USING (id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);

            ALTER TABLE platform.organization_modules ENABLE ROW LEVEL SECURITY;
            CREATE POLICY comuni_tenant_isolation ON platform.organization_modules
                FOR ALL TO PUBLIC
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);

            ALTER TABLE platform.organization_memberships ENABLE ROW LEVEL SECURITY;
            CREATE POLICY comuni_tenant_isolation ON platform.organization_memberships
                FOR ALL TO PUBLIC
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);

            ALTER TABLE protocol.records ENABLE ROW LEVEL SECURITY;
            CREATE POLICY comuni_tenant_isolation ON protocol.records
                FOR ALL TO PUBLIC
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);

            ALTER TABLE platform.audit_events ENABLE ROW LEVEL SECURITY;
            CREATE POLICY comuni_tenant_isolation ON platform.audit_events
                FOR ALL TO PUBLIC
                USING (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid)
                WITH CHECK (organization_id = NULLIF(current_setting('comuni.organization_id', TRUE), '')::uuid);
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DROP POLICY comuni_tenant_isolation ON platform.audit_events;
            ALTER TABLE platform.audit_events DISABLE ROW LEVEL SECURITY;

            DROP POLICY comuni_tenant_isolation ON protocol.records;
            ALTER TABLE protocol.records DISABLE ROW LEVEL SECURITY;

            DROP POLICY comuni_tenant_isolation ON platform.organization_memberships;
            ALTER TABLE platform.organization_memberships DISABLE ROW LEVEL SECURITY;

            DROP POLICY comuni_tenant_isolation ON platform.organization_modules;
            ALTER TABLE platform.organization_modules DISABLE ROW LEVEL SECURITY;

            DROP POLICY comuni_tenant_isolation ON platform.organizations;
            ALTER TABLE platform.organizations DISABLE ROW LEVEL SECURITY;
            """);
    }
}

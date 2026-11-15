using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Comuni.Domains.Protocol;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Runs against a real PostgreSQL LOGIN account, distinct from the migration owner.
/// CI must provision that account after EF migrations, before these tests.
/// </summary>
public sealed class RuntimeDatabasePrivilegesTests
{
    private static string RuntimeConnection =>
        Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_RUNTIME_DATABASE_CONNECTION is required for least-privilege tests.");

    private static string AdminConnection =>
        Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION is required for fixture seeding.");

    [Fact]
    public async Task Runtime_login_has_explicit_allowlisted_privileges_and_no_ownership_or_ddl()
    {
        await using var connection = new NpgsqlConnection(RuntimeConnection);
        await connection.OpenAsync();

        await using (var role = new NpgsqlCommand("""
            SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
            FROM pg_roles WHERE rolname = current_user
            """, connection))
        await using (var reader = await role.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            Assert.Equal("comuni_app_runtime", reader.GetString(0));
            Assert.True(reader.GetBoolean(1));
            for (var index = 2; index <= 6; index++)
                Assert.False(reader.GetBoolean(index));
        }

        await using var rights = new NpgsqlCommand("""
            SELECT
                has_schema_privilege(current_user, 'platform', 'USAGE'),
                has_schema_privilege(current_user, 'protocol', 'USAGE'),
                has_schema_privilege(current_user, 'platform', 'CREATE'),
                has_table_privilege(current_user, 'platform.organizations', 'SELECT'),
                has_table_privilege(current_user, 'platform.organizations', 'UPDATE'),
                has_table_privilege(current_user, 'platform.organization_memberships', 'SELECT'),
                has_table_privilege(current_user, 'platform.organization_memberships', 'INSERT'),
                has_table_privilege(current_user, 'platform.organization_modules', 'SELECT'),
                has_column_privilege(current_user, 'platform.organization_modules', 'enabled', 'UPDATE'),
                has_column_privilege(current_user, 'platform.organization_modules', 'module_key', 'UPDATE'),
                has_table_privilege(current_user, 'protocol.records', 'SELECT'),
                has_table_privilege(current_user, 'protocol.records', 'INSERT'),
                has_table_privilege(current_user, 'protocol.records', 'DELETE'),
                has_table_privilege(current_user, 'platform.audit_events', 'INSERT'),
                has_table_privilege(current_user, 'platform.audit_events', 'SELECT'),
                has_table_privilege(current_user, 'platform.audit_events', 'UPDATE'),
                has_table_privilege(current_user, 'platform.audit_events', 'DELETE'),
                has_table_privilege(current_user, 'public."__EFMigrationsHistory"', 'SELECT')
            """, connection);
        await using var permissions = await rights.ExecuteReaderAsync();
        Assert.True(await permissions.ReadAsync());
        var allow = new[] { 0, 1, 3, 5, 7, 8, 10, 11, 13 };
        for (var i = 0; i <= 17; i++)
            Assert.Equal(allow.Contains(i), permissions.GetBoolean(i));
    }

    [Fact]
    public async Task Runtime_EF_can_read_organization_and_write_protocol_audit_and_module_flags()
    {
        var org = await SeedOrganizationAsync();
        var options = new DbContextOptionsBuilder<ComuniDbContext>()
            .UseNpgsql(RuntimeConnection).Options;
        await using var db = new ComuniDbContext(options, new CurrentTestOrganization(org));
        await using var tenant = await TenantDatabaseTransaction.BeginAsync(db, CancellationToken.None);

        Assert.True(await db.Organizations.AsNoTracking().AnyAsync(x => x.Id == org));
        Assert.True(await db.OrganizationMemberships.AsNoTracking()
            .AnyAsync(x => x.OrganizationId == org && x.Subject == "runtime-test-admin"));
        Assert.True(await db.OrganizationModules.AsNoTracking()
            .AnyAsync(x => x.OrganizationId == org && x.ModuleKey == "protocol" && x.Enabled));

        var record = ProtocolRecord.Register(org, "Runtime least-privilege test");
        var audit = AuditEvent.Create(org, "runtime-test-admin", "protocol.record.created",
            "protocol.record", record.Id, "runtime-record-test");
        await new ProtocolRepository(db).AddAsync(record, audit, CancellationToken.None);

        var service = new ModuleAdministrationRepository(db);
        var moduleAudit = AuditEvent.Create(org, "runtime-test-admin",
            "platform.module.protocol.disabled", "platform.module", org, "runtime-module-test");
        Assert.Equal(ModuleUpdateStatus.Updated,
            await service.SetEnabledAsync(org, "protocol", false, moduleAudit, CancellationToken.None));

        await tenant.CommitAsync();
        await using var admin = new NpgsqlConnection(AdminConnection);
        await admin.OpenAsync();
        await using var check = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM protocol.records WHERE id = @record) = 1
                AND (SELECT count(*) FROM platform.audit_events WHERE resource_id = @record
                     AND organization_id = @org) = 1
                AND (SELECT count(*) FROM platform.audit_events WHERE correlation_id = 'runtime-module-test'
                     AND organization_id = @org) = 1
                AND (SELECT enabled FROM platform.organization_modules
                     WHERE organization_id = @org AND module_key = 'protocol') = FALSE
            """, admin);
        check.Parameters.AddWithValue("record", record.Id);
        check.Parameters.AddWithValue("org", org);
        Assert.True((bool)(await check.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Runtime_SQL_cannot_change_memberships_organizations_audit_or_database_schema()
    {
        var org = await SeedOrganizationAsync();
        await using var connection = new NpgsqlConnection(RuntimeConnection);
        await connection.OpenAsync();

        var forbidden = new[]
        {
            "CREATE TABLE platform.runtime_forbidden (id integer)",
            "ALTER TABLE platform.organizations ADD COLUMN runtime_forbidden integer",
            $"UPDATE platform.organizations SET name = 'forged' WHERE id = '{org}'",
            $"INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES ('{org}', 'forged', 'Admin', true)",
            "SELECT count(*) FROM platform.audit_events",
            $"DELETE FROM protocol.records WHERE organization_id = '{org}'",
            "SELECT count(*) FROM public.\"__EFMigrationsHistory\""
        };
        foreach (var sql in forbidden)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            var failure = await Assert.ThrowsAsync<PostgresException>(
                () => command.ExecuteNonQueryAsync());
            Assert.Equal("42501", failure.SqlState);
        }
    }

    private static async Task<Guid> SeedOrganizationAsync()
    {
        var org = Guid.NewGuid();
        await using var admin = new NpgsqlConnection(AdminConnection);
        await admin.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name) VALUES (@org, 'Comune test privilegi');
            INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
                VALUES (@org, 'protocol', TRUE);
            INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active)
                VALUES (@org, 'runtime-test-admin', 'Admin', TRUE);
            """, admin);
        command.Parameters.AddWithValue("org", org);
        await command.ExecuteNonQueryAsync();
        return org;
    }

    private sealed class CurrentTestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }
}

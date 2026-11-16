using System.Diagnostics;
using System.Net;
using Comuni.Business.Organizations;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// TDD for created → active → suspended, using real PostgreSQL 17 and owner psql.
/// No Azure deployment, external OIDC issuer, or real municipality identities.
/// </summary>
public sealed class OrganizationActivationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner connection required.");

    private static string Script(string name)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "AGENTS.md")))
                return Path.Combine(d.FullName, "scripts", "postgres", name);
        throw new InvalidOperationException("Project root missing.");
    }

    private static async Task<(int Code, string Output)> ExecuteAsync(string name, Guid org,
        string? ticket = "CHANGE-2026-00044", string? approver = "independent-reviewer",
        string? connection = null)
    {
        var file = Script(name);
        Assert.True(File.Exists(file), "RED: owner activation procedure has not been implemented.");
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host,
            "-p", db.Port.ToString(), "-U", db.Username, "-d", db.Database, "-f", file
        }) start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = db.Password;
        void Env(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Env("COMUNI_REGISTER_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_REGISTER_ORGANIZATION_NAME", "Comune Sintetico Attivazione");
        Env("COMUNI_REGISTER_CHANGE_TICKET", ticket);
        Env("COMUNI_REGISTER_APPROVER", approver);
        Env("COMUNI_BOOTSTRAP_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_BOOTSTRAP_IDENTITY_ISSUER", "https://identity.example.test/tenant/v2.0");
        Env("COMUNI_BOOTSTRAP_SUBJECT", "synthetic-first-admin");
        Env("COMUNI_BOOTSTRAP_CHANGE_TICKET", "CHANGE-2026-ADMIN44");
        Env("COMUNI_BOOTSTRAP_APPROVER", "independent-reviewer");
        Env("COMUNI_ACTIVATE_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_ACTIVATE_CHANGE_TICKET", ticket);
        Env("COMUNI_ACTIVATE_APPROVER", approver);
        Env("COMUNI_LIFECYCLE_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_LIFECYCLE_ACTION", "reactivate");
        Env("COMUNI_LIFECYCLE_CHANGE_TICKET", ticket);
        Env("COMUNI_LIFECYCLE_APPROVER", approver);
        Env("COMUNI_LIFECYCLE_REASON_CODE", "approved-lifecycle");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("psql failed to start");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static Task<(int Code, string Output)> Register(Guid org) =>
        ExecuteAsync("register-organization.sql", org);
    private static Task<(int Code, string Output)> Bootstrap(Guid org) =>
        ExecuteAsync("bootstrap-initial-admin.sql", org);
    private static Task<(int Code, string Output)> Activate(Guid org,
        string? ticket = "CHANGE-2026-00044", string? reviewer = "independent-reviewer",
        string? connection = null) =>
        ExecuteAsync("activate-organization.sql", org, ticket, reviewer, connection);

    private static async Task<(bool Activated, bool Suspended, bool ModuleEnabled,
        long Admins, long Activations)> ReadAsync(Guid org)
    {
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT
                (SELECT is_activated FROM platform.organizations WHERE id=@id),
                (SELECT is_suspended FROM platform.organizations WHERE id=@id),
                (SELECT enabled FROM platform.organization_modules WHERE organization_id=@id AND module_key='protocol'),
                (SELECT COUNT(*) FROM platform.organization_memberships WHERE organization_id=@id AND role='Admin' AND is_active),
                (SELECT COUNT(*) FROM platform.audit_events WHERE organization_id=@id AND action='platform.organization.activated')
            """, connection);
        cmd.Parameters.AddWithValue("id", org);
        await using var rows = await cmd.ExecuteReaderAsync();
        Assert.True(await rows.ReadAsync());
        return (rows.GetBoolean(0), rows.GetBoolean(1), rows.GetBoolean(2),
            rows.GetInt64(3), rows.GetInt64(4));
    }

    [Fact]
    public async Task New_organization_is_created_and_denied_even_after_Admin_bootstrap_until_owner_activation()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await Register(id)).Code);
        Assert.Equal((false, false, false, 0L, 0L), await ReadAsync(id));

        Assert.Equal(0, (await Bootstrap(id)).Code);
        Assert.Equal((false, false, false, 1L, 0L), await ReadAsync(id));

        // Test-only legacy membership uses the DevelopmentJwt issuer; the
        // production bootstrap Admin remains separately bound to OIDC issuer.
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var add = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id,subject,role,is_active)
                VALUES (@org,'test-reader','Reader',TRUE)
                """, db);
            add.Parameters.AddWithValue("org", id);
            await add.ExecuteNonQueryAsync();
        }
        using var reader = factory.ClientFor(id.ToString(), "Reader", "test-reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);
        using (var scope = factory.Services.CreateScope())
        {
            var directory = scope.ServiceProvider.GetRequiredService<IOrganizationDirectory>();
            Assert.False(await directory.IsOperationalAsync(id, CancellationToken.None));
        }

        var activated = await Activate(id);
        Assert.Equal(0, activated.Code);
        Assert.DoesNotContain("CHANGE-2026-00044", activated.Output);
        Assert.DoesNotContain(id.ToString("D"), activated.Output);
        Assert.Equal((true, false, false, 1L, 1L), await ReadAsync(id));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);

        Assert.Equal(0, (await Activate(id)).Code);
        Assert.Equal((true, false, false, 1L, 1L), await ReadAsync(id));

        await using var check = new NpgsqlConnection(Owner);
        await check.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT actor_subject, resource_type, resource_id, correlation_id
            FROM platform.audit_events
            WHERE organization_id=@id AND action='platform.organization.activated'
            """, check);
        query.Parameters.AddWithValue("id", id);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.StartsWith("db-owner:", row.GetString(0));
        Assert.Equal("platform.organization", row.GetString(1));
        Assert.Equal(id, row.GetGuid(2));
        Assert.Equal("activation:CHANGE-2026-00044", row.GetString(3));
        Assert.False(await row.ReadAsync());
    }

    [Fact]
    public async Task Activation_rejects_absent_or_legacy_Admin_and_enabled_module_without_writes()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await Register(id)).Code);
        Assert.NotEqual(0, (await Activate(id)).Code);
        Assert.Equal((false, false, false, 0L, 0L), await ReadAsync(id));

        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var legacy = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id,subject,role,is_active,identity_issuer)
                VALUES (@id,'legacy-admin','Admin',TRUE,NULL)
                """, db);
            legacy.Parameters.AddWithValue("id", id);
            await legacy.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Activate(id)).Code);
        Assert.Equal(0L, (await ReadAsync(id)).Activations);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var upgrade = new NpgsqlCommand("""
                UPDATE platform.organization_memberships
                SET identity_issuer='https://identity.example.test/tenant/v2.0'
                WHERE organization_id=@id AND role='Admin'
                """, db);
            upgrade.Parameters.AddWithValue("id", id);
            await upgrade.ExecuteNonQueryAsync();
            await using var module = new NpgsqlCommand("""
                UPDATE platform.organization_modules
                SET enabled=TRUE WHERE organization_id=@id AND module_key='protocol'
                """, db);
            module.Parameters.AddWithValue("id", id);
            await module.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Activate(id)).Code);
        Assert.Equal((false, false, true, 1L, 0L), await ReadAsync(id));
    }

    [Fact]
    public async Task Unauthorized_runtime_invalid_approval_unknown_and_pending_reactivation_fail()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await Register(id)).Code);
        Assert.Equal(0, (await Bootstrap(id)).Code);

        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")!;
        Assert.NotEqual(0, (await Activate(id, connection: runtime)).Code);
        Assert.NotEqual(0, (await Activate(id, ticket: null)).Code);
        Assert.NotEqual(0, (await Activate(id, reviewer: null)).Code);
        Assert.NotEqual(0, (await Activate(id, ticket: "bad ticket")).Code);
        Assert.NotEqual(0, (await Activate(Guid.NewGuid())).Code);
        Assert.NotEqual(0, (await Activate(Guid.Empty)).Code);

        var pendingReactivate = await ExecuteAsync("set-organization-suspension.sql", id);
        Assert.NotEqual(0, pendingReactivate.Code);
        Assert.Equal((false, false, false, 1L, 0L), await ReadAsync(id));
    }

    [Fact]
    public async Task Concurrent_owner_activation_produces_one_audit_without_state_corruption()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await Register(id)).Code);
        Assert.Equal(0, (await Bootstrap(id)).Code);
        var both = await Task.WhenAll(Activate(id), Activate(id));
        Assert.All(both, result => Assert.Equal(0, result.Code));
        Assert.Equal((true, false, false, 1L, 1L), await ReadAsync(id));
    }

    [Fact]
    public async Task Existing_legacy_suspended_and_active_organizations_remain_activated_after_migration()
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        var active = Guid.NewGuid();
        var suspended = Guid.NewGuid();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id,name,is_suspended) VALUES
                (@a,'Legacy Active',FALSE), (@b,'Legacy Suspended',TRUE);
            """, db);
        insert.Parameters.AddWithValue("a", active);
        insert.Parameters.AddWithValue("b", suspended);
        await insert.ExecuteNonQueryAsync();
        var a = await ReadAsyncWithoutModule(active);
        var b = await ReadAsyncWithoutModule(suspended);
        Assert.Equal((true, false), a);
        Assert.Equal((true, true), b);
    }

    private static async Task<(bool Activated, bool Suspended)> ReadAsyncWithoutModule(Guid id)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var query = new NpgsqlCommand(
            "SELECT is_activated,is_suspended FROM platform.organizations WHERE id=@id", db);
        query.Parameters.AddWithValue("id", id);
        await using var rows = await query.ExecuteReaderAsync();
        Assert.True(await rows.ReadAsync());
        return (rows.GetBoolean(0), rows.GetBoolean(1));
    }

    [Fact]
    public async Task Platform_inventory_compatibility_marks_pending_as_not_operational()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await Register(id)).Code);
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT is_suspended,protocol_enabled
            FROM platform.platform_organization_inventory WHERE id=@id
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var rows = await cmd.ExecuteReaderAsync();
        Assert.True(await rows.ReadAsync());
        Assert.True(rows.GetBoolean(0)); // effective non-operational in legacy field
        Assert.False(rows.GetBoolean(1));
    }
}

using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Owner-only lifecycle contracts on disposable PostgreSQL with real psql.
/// No production identities or Azure environment are touched.
/// </summary>
public sealed class OrganizationLifecycleTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static string OwnerConnection => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL TEST_DATABASE_CONNECTION required.");
    private static string RuntimeConnection => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted PostgreSQL runtime connection required.");

    private static string ScriptPath
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                    return Path.Combine(dir.FullName, "scripts/postgres/set-organization-suspension.sql");
            throw new InvalidOperationException("Repository root not found.");
        }
    }

    private static async Task<Guid> SeedAsync(bool suspended = false)
    {
        var org = Guid.NewGuid();
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name, is_suspended)
                VALUES (@org, 'Comune di Test Lifecycle', @suspended);
            INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
                VALUES (@org, 'protocol', TRUE);
            INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active)
                VALUES (@org, 'test-admin', 'Admin', TRUE),
                       (@org, 'test-reader', 'Reader', TRUE),
                       (@org, 'disabled', 'Reader', FALSE);
            """, db);
        cmd.Parameters.AddWithValue("org", org);
        cmd.Parameters.AddWithValue("suspended", suspended);
        await cmd.ExecuteNonQueryAsync();
        return org;
    }

    private static async Task<(int Code, string Output)> LifecycleAsync(
        Guid org, string? action = "suspend",
        string? ticket = "CHANGE-2026-00033", string? approver = "independent-reviewer",
        string? reason = "security-incident", string? connection = null)
    {
        Assert.True(File.Exists(ScriptPath), "Owner-only lifecycle SQL script is missing.");
        var builder = new NpgsqlConnectionStringBuilder(connection ?? OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", builder.Host,
            "-p", builder.Port.ToString(), "-U", builder.Username, "-d", builder.Database,
            "-f", ScriptPath
        })
            start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = builder.Password;
        start.Environment["COMUNI_LIFECYCLE_ORGANIZATION_ID"] = org.ToString("D");
        void SetOptional(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        SetOptional("COMUNI_LIFECYCLE_ACTION", action);
        SetOptional("COMUNI_LIFECYCLE_CHANGE_TICKET", ticket);
        SetOptional("COMUNI_LIFECYCLE_APPROVER", approver);
        SetOptional("COMUNI_LIFECYCLE_REASON_CODE", reason);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Could not run psql.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(bool Suspended, bool ProtocolEnabled,
        long ActiveMembers, long Suspends, long Reactivations)> StateAsync(Guid id)
    {
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT
                (SELECT is_suspended FROM platform.organizations WHERE id = @id),
                (SELECT enabled FROM platform.organization_modules
                 WHERE organization_id = @id AND module_key = 'protocol'),
                (SELECT COUNT(*) FROM platform.organization_memberships
                 WHERE organization_id = @id AND is_active),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id = @id AND action = 'platform.organization.suspended'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id = @id AND action = 'platform.organization.reactivated')
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetBoolean(0), reader.GetBoolean(1),
            reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4));
    }

    [Fact]
    public async Task Suspension_blocks_all_protected_routes_without_revoking_other_tenants_and_reactivation_restores_only_existing_rights()
    {
        var id = await SeedAsync();
        using var admin = factory.ClientFor(id.ToString(), "Admin", "test-admin");
        using var reader = factory.ClientFor(id.ToString(), "Reader", "test-reader");
        using var disabled = factory.ClientFor(id.ToString(), "Admin", "disabled");
        using var unrelated = factory.ClientFor(ApiFactory.OrgA, "Reader");

        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await disabled.GetAsync("/api/v1/context")).StatusCode);

        var suspended = await LifecycleAsync(id);
        Assert.Equal(0, suspended.Code);
        Assert.DoesNotContain("CHANGE-2026-00033", suspended.Output);
        Assert.DoesNotContain("security-incident", suspended.Output);
        Assert.Equal((true, true, 2L, 1L, 0L), await StateAsync(id));
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.GetAsync("/api/v1/admin/memberships")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PostAsJsonAsync("/api/v1/protocol/records",
            new { subject = "Denegato" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await unrelated.GetAsync("/api/v1/context")).StatusCode);

        Assert.Equal(0, (await LifecycleAsync(id, "reactivate")).Code);
        Assert.Equal((false, true, 2L, 1L, 1L), await StateAsync(id));
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await disabled.GetAsync("/api/v1/context")).StatusCode);

        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT actor_subject, resource_type, resource_id, correlation_id
            FROM platform.audit_events
            WHERE organization_id = @id
              AND action IN ('platform.organization.suspended', 'platform.organization.reactivated')
            ORDER BY occurred_at
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var rows = await cmd.ExecuteReaderAsync();
        var total = 0;
        while (await rows.ReadAsync())
        {
            Assert.StartsWith("db-owner:", rows.GetString(0));
            Assert.Equal("platform.organization", rows.GetString(1));
            Assert.Equal(id, rows.GetGuid(2));
            Assert.Equal("lifecycle:CHANGE-2026-00033", rows.GetString(3));
            total++;
        }
        Assert.Equal(2, total);
    }

    [Fact]
    public async Task Repeated_and_concurrent_actions_are_idempotent_and_do_not_touch_flags()
    {
        var id = await SeedAsync();
        var first = await Task.WhenAll(LifecycleAsync(id), LifecycleAsync(id));
        Assert.All(first, result => Assert.Equal(0, result.Code));
        Assert.Equal((true, true, 2L, 1L, 0L), await StateAsync(id));
        Assert.Equal(0, (await LifecycleAsync(id)).Code);
        Assert.Equal((true, true, 2L, 1L, 0L), await StateAsync(id));

        var second = await Task.WhenAll(
            LifecycleAsync(id, "reactivate"), LifecycleAsync(id, "reactivate"));
        Assert.All(second, result => Assert.Equal(0, result.Code));
        Assert.Equal((false, true, 2L, 1L, 1L), await StateAsync(id));
    }

    [Fact]
    public async Task Unknown_invalid_or_unapproved_operations_fail_closed_without_audit()
    {
        var id = await SeedAsync();
        Assert.NotEqual(0, (await LifecycleAsync(Guid.Empty)).Code);
        Assert.NotEqual(0, (await LifecycleAsync(Guid.NewGuid())).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, action: null)).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, action: "delete")).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, action: "SuspEnd")).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, ticket: null)).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, ticket: "bad ticket")).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, approver: null)).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, reason: null)).Code);
        Assert.NotEqual(0, (await LifecycleAsync(id, reason: "security'; DROP TABLE platform.organizations;--")).Code);
        Assert.Equal((false, true, 2L, 0L, 0L), await StateAsync(id));
    }

    [Fact]
    public async Task Database_runtime_is_forbidden_even_if_an_operator_supplies_approval_fields()
    {
        var id = await SeedAsync();
        Assert.NotEqual(0, (await LifecycleAsync(id, connection: RuntimeConnection)).Code);
        Assert.Equal((false, true, 2L, 0L, 0L), await StateAsync(id));
    }

    [Fact]
    public async Task Repeated_reactivation_of_already_active_tenant_is_noop()
    {
        var id = await SeedAsync();
        Assert.Equal(0, (await LifecycleAsync(id, "reactivate")).Code);
        Assert.Equal((false, true, 2L, 0L, 0L), await StateAsync(id));
    }
}

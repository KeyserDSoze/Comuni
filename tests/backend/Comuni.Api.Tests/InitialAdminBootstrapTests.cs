using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Tests the owner-only first Admin bootstrap against the real PostgreSQL 17 test database.
/// All identities and change tickets are synthetic; no IdP is contacted.
/// </summary>
public sealed class InitialAdminBootstrapTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL TEST_DATABASE_CONNECTION required.");

    private static string ScriptPath
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory);
                 dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                    return Path.Combine(dir.FullName, "scripts", "postgres", "bootstrap-initial-admin.sql");
            }
            throw new InvalidOperationException("Repository root was not found.");
        }
    }

    private static async Task<Guid> SeedOrganizationAsync(bool suspended = false,
        string? existingAdmin = null, bool adminActive = false)
    {
        var org = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using (var command = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name, is_suspended)
                VALUES (@org, 'Comune bootstrap sintetico', @suspended)
            """, connection))
        {
            command.Parameters.AddWithValue("org", org);
            command.Parameters.AddWithValue("suspended", suspended);
            await command.ExecuteNonQueryAsync();
        }
        if (existingAdmin is not null)
        {
            await using var command = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id, subject, role, is_active, identity_issuer)
                VALUES (@org, @subject, 'Admin', @enabled, NULL)
                """, connection);
            command.Parameters.AddWithValue("org", org);
            command.Parameters.AddWithValue("subject", existingAdmin);
            command.Parameters.AddWithValue("enabled", adminActive);
            await command.ExecuteNonQueryAsync();
        }
        return org;
    }

    private static async Task<(int ExitCode, string Output)> BootstrapAsync(
        Guid org, string? issuer = "https://identity.example.test/tenant/v2.0",
        string? subject = "synthetic-first-admin", string? ticket = "CHANGE-2026-00031",
        string? reviewer = "security-reviewer", string? connectionOverride = null)
    {
        var script = ScriptPath;
        Assert.True(File.Exists(script), "Owner-only bootstrap script missing.");
        var db = new NpgsqlConnectionStringBuilder(connectionOverride ?? ConnectionString);
        var start = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", db.Host, "-p", db.Port.ToString(),
            "-U", db.Username, "-d", db.Database,
            "-f", script
        })
            start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = db.Password;
        start.Environment["COMUNI_BOOTSTRAP_ORGANIZATION_ID"] = org.ToString("D");
        if (issuer is not null) start.Environment["COMUNI_BOOTSTRAP_IDENTITY_ISSUER"] = issuer;
        else start.Environment.Remove("COMUNI_BOOTSTRAP_IDENTITY_ISSUER");
        if (subject is not null) start.Environment["COMUNI_BOOTSTRAP_SUBJECT"] = subject;
        else start.Environment.Remove("COMUNI_BOOTSTRAP_SUBJECT");
        if (ticket is not null) start.Environment["COMUNI_BOOTSTRAP_CHANGE_TICKET"] = ticket;
        else start.Environment.Remove("COMUNI_BOOTSTRAP_CHANGE_TICKET");
        if (reviewer is not null) start.Environment["COMUNI_BOOTSTRAP_APPROVER"] = reviewer;
        else start.Environment.Remove("COMUNI_BOOTSTRAP_APPROVER");

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("psql process could not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(long Admins, long Audit)> CountsAsync(Guid org)
    {
        await using var conn = new NpgsqlConnection(ConnectionString);
        await conn.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT
              (SELECT COUNT(*) FROM platform.organization_memberships
               WHERE organization_id = @org AND role = 'Admin'),
              (SELECT COUNT(*) FROM platform.audit_events
               WHERE organization_id = @org AND action = 'platform.membership.admin.initialized')
            """, conn);
        query.Parameters.AddWithValue("org", org);
        await using var reader = await query.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    [Fact]
    public async Task First_verified_oidc_Admin_is_atomic_and_same_input_retry_is_idempotent()
    {
        var org = await SeedOrganizationAsync();
        var first = await BootstrapAsync(org);
        Assert.Equal(0, first.ExitCode);
        Assert.DoesNotContain("synthetic-first-admin", first.Output);
        Assert.DoesNotContain("identity.example.test", first.Output);
        Assert.DoesNotContain("CHANGE-2026-00031", first.Output);
        Assert.Equal((1L, 1L), await CountsAsync(org));

        var retry = await BootstrapAsync(org);
        Assert.Equal(0, retry.ExitCode);
        Assert.Equal((1L, 1L), await CountsAsync(org));

        await using var conn = new NpgsqlConnection(ConnectionString);
        await conn.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT subject, identity_issuer, is_active FROM platform.organization_memberships
            WHERE organization_id = @org AND role = 'Admin'
            """, conn);
        query.Parameters.AddWithValue("org", org);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.Equal("synthetic-first-admin", row.GetString(0));
        Assert.Equal("https://identity.example.test/tenant/v2.0", row.GetString(1));
        Assert.True(row.GetBoolean(2));
    }

    [Fact]
    public async Task Cannot_grant_second_Admin_or_transfer_legacy_disabled_Admin()
    {
        var org = await SeedOrganizationAsync();
        Assert.Equal(0, (await BootstrapAsync(org)).ExitCode);
        Assert.NotEqual(0, (await BootstrapAsync(org, subject: "attacker-second-admin")).ExitCode);
        Assert.Equal((1L, 1L), await CountsAsync(org));

        var legacy = await SeedOrganizationAsync(existingAdmin: "unbound-admin", adminActive: false);
        Assert.NotEqual(0, (await BootstrapAsync(legacy)).ExitCode);
        Assert.Equal((1L, 0L), await CountsAsync(legacy));
    }

    [Fact]
    public async Task Unknown_or_suspended_organization_and_invalid_attestation_refuse_without_writes()
    {
        var unknown = Guid.NewGuid();
        Assert.NotEqual(0, (await BootstrapAsync(unknown)).ExitCode);
        Assert.Equal((0L, 0L), await CountsAsync(unknown));

        var suspended = await SeedOrganizationAsync(suspended: true);
        Assert.NotEqual(0, (await BootstrapAsync(suspended)).ExitCode);
        Assert.Equal((0L, 0L), await CountsAsync(suspended));

        var org = await SeedOrganizationAsync();
        Assert.NotEqual(0, (await BootstrapAsync(org, issuer: "http://identity.example.test")).ExitCode);
        Assert.NotEqual(0, (await BootstrapAsync(org, issuer: "https://evil.test@identity.example.test")).ExitCode);
        Assert.NotEqual(0, (await BootstrapAsync(org, subject: " signed-in-admin ")).ExitCode);
        Assert.NotEqual(0, (await BootstrapAsync(org, ticket: null)).ExitCode);
        Assert.NotEqual(0, (await BootstrapAsync(org, reviewer: null)).ExitCode);
        Assert.Equal((0L, 0L), await CountsAsync(org));
    }

    [Fact]
    public async Task Restricted_runtime_database_login_cannot_bootstrap_Admin()
    {
        var org = await SeedOrganizationAsync();
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted runtime connection required.");

        var attempted = await BootstrapAsync(org, connectionOverride: runtime);
        Assert.NotEqual(0, attempted.ExitCode);
        Assert.Equal((0L, 0L), await CountsAsync(org));
    }

    [Fact]
    public async Task Concurrent_first_Admin_attempts_can_only_create_one_member_and_one_audit()
    {
        var org = await SeedOrganizationAsync();
        var results = await Task.WhenAll(
            BootstrapAsync(org, subject: "first-candidate"),
            BootstrapAsync(org, subject: "second-candidate")
        );
        Assert.Single(results.Where(x => x.ExitCode == 0));
        Assert.Equal((1L, 1L), await CountsAsync(org));
    }
}

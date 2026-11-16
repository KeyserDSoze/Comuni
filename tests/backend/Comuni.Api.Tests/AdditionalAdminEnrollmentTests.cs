using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first PostgreSQL integration contract for a second OIDC Admin enrollment.
/// No real IdP, tenant data, Azure connection or owner production credentials.
/// </summary>
public sealed class AdditionalAdminEnrollmentTests
{
    private const string Issuer = "https://identity.example.test/tenant/v2.0";
    private const string Initial = "synthetic-initial-admin";
    private const string Second = "synthetic-second-admin";
    private const string Ticket = "CHANGE-2026-00080";

    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner connection is required.");

    private static string Root()
    {
        for (var path = new DirectoryInfo(AppContext.BaseDirectory);
             path is not null; path = path.Parent)
            if (File.Exists(Path.Combine(path.FullName, "AGENTS.md")))
                return path.FullName;
        throw new InvalidOperationException("Repository root missing.");
    }

    private static async Task<(int Code, string Output)> Run(
        string file, Guid organization, string? issuer = Issuer, string? subject = Second,
        string? ticket = Ticket, string? reviewer = "independent-reviewer",
        string? connection = null)
    {
        var script = Path.Combine(Root(), "scripts", "postgres", file);
        Assert.True(File.Exists(script), "RED: additional Admin enrollment must be implemented.");
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var processInfo = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", db.Host, "-p", db.Port.ToString(),
            "-U", db.Username, "-d", db.Database, "-f", script
        })
            processInfo.ArgumentList.Add(arg);
        processInfo.Environment["PGPASSWORD"] = db.Password;
        void SetEnv(string name, string? value)
        {
            if (value is null) processInfo.Environment.Remove(name);
            else processInfo.Environment[name] = value;
        }
        SetEnv("COMUNI_BOOTSTRAP_ORGANIZATION_ID", organization.ToString("D"));
        SetEnv("COMUNI_BOOTSTRAP_IDENTITY_ISSUER", Issuer);
        SetEnv("COMUNI_BOOTSTRAP_SUBJECT", Initial);
        SetEnv("COMUNI_BOOTSTRAP_CHANGE_TICKET", "CHANGE-2026-FIRST80");
        SetEnv("COMUNI_BOOTSTRAP_APPROVER", "independent-reviewer");
        SetEnv("COMUNI_ADD_ADMIN_ORGANIZATION_ID", organization.ToString("D"));
        SetEnv("COMUNI_ADD_ADMIN_IDENTITY_ISSUER", issuer);
        SetEnv("COMUNI_ADD_ADMIN_SUBJECT", subject);
        SetEnv("COMUNI_ADD_ADMIN_CHANGE_TICKET", ticket);
        SetEnv("COMUNI_ADD_ADMIN_APPROVER", reviewer);
        using var process = Process.Start(processInfo)
            ?? throw new InvalidOperationException("psql process did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<Guid> Seed(bool activated = true, bool suspended = false)
    {
        var org = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name, is_activated, is_suspended)
            VALUES (@org, 'Comune sintetico add Admin', @activated, @suspended)
            """, connection);
        cmd.Parameters.AddWithValue("org", org);
        cmd.Parameters.AddWithValue("activated", activated);
        cmd.Parameters.AddWithValue("suspended", suspended);
        await cmd.ExecuteNonQueryAsync();
        return org;
    }

    private static Task<(int Code, string Output)> Bootstrap(Guid org) =>
        Run("bootstrap-initial-admin.sql", org);

    private static Task<(int Code, string Output)> Add(Guid org,
        string? issuer = Issuer, string? subject = Second, string? ticket = Ticket,
        string? reviewer = "independent-reviewer", string? connection = null) =>
        Run("enroll-additional-admin.sql", org, issuer, subject, ticket, reviewer, connection);

    private static async Task<(long Admins, long Active, long Added, long Initialized)> Counts(Guid org)
    {
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT
              (SELECT count(*) FROM platform.organization_memberships
               WHERE organization_id=@org AND role='Admin'),
              (SELECT count(*) FROM platform.organization_memberships
               WHERE organization_id=@org AND role='Admin' AND is_active),
              (SELECT count(*) FROM platform.audit_events
               WHERE organization_id=@org AND action='platform.membership.admin.added'),
              (SELECT count(*) FROM platform.audit_events
               WHERE organization_id=@org AND action='platform.membership.admin.initialized')
            """, connection);
        command.Parameters.AddWithValue("org", org);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1),
                reader.GetInt64(2), reader.GetInt64(3));
    }

    [Fact]
    public async Task Second_Admin_is_atomic_audited_and_exact_ticket_retry_is_noop()
    {
        var org = await Seed();
        Assert.Equal(0, (await Bootstrap(org)).Code);
        var first = await Add(org);
        Assert.Equal(0, first.Code);
        foreach (var secret in new[] { Issuer, Second, Ticket, org.ToString("D") })
            Assert.DoesNotContain(secret, first.Output);
        Assert.Equal((2L, 2L, 1L, 1L), await Counts(org));
        Assert.Equal(0, (await Add(org)).Code);
        Assert.Equal((2L, 2L, 1L, 1L), await Counts(org));

        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var readerCmd = new NpgsqlCommand("""
            SELECT m.subject, m.identity_issuer, m.is_active
            FROM platform.organization_memberships m
            WHERE m.organization_id=@org AND role='Admin' ORDER BY subject
            """, db);
        readerCmd.Parameters.AddWithValue("org", org);
        var names = new List<string>();
        await using (var rows = await readerCmd.ExecuteReaderAsync())
        {
            while (await rows.ReadAsync())
            {
                names.Add(rows.GetString(0));
                Assert.Equal(Issuer, rows.GetString(1));
                Assert.True(rows.GetBoolean(2));
            }
        }
        Assert.Equal(new[] { Initial, Second }, names);

        await using var eventCmd = new NpgsqlCommand("""
            SELECT actor_subject, correlation_id, resource_type
            FROM platform.audit_events
            WHERE organization_id=@org AND action='platform.membership.admin.added'
            """, db);
        eventCmd.Parameters.AddWithValue("org", org);
        await using var audit = await eventCmd.ExecuteReaderAsync();
        Assert.True(await audit.ReadAsync());
        Assert.StartsWith("db-owner:", audit.GetString(0));
        Assert.Equal("admin-enroll:" + Ticket, audit.GetString(1));
        Assert.Equal("platform.membership", audit.GetString(2));
        Assert.False(await audit.ReadAsync());
    }

    [Fact]
    public async Task Changed_issuer_ticket_or_target_cannot_reuse_an_enrollment()
    {
        var org = await Seed();
        Assert.Equal(0, (await Bootstrap(org)).Code);
        Assert.Equal(0, (await Add(org)).Code);
        Assert.NotEqual(0, (await Add(org, ticket: "CHANGE-2026-DIFFERENT80")).Code);
        Assert.NotEqual(0, (await Add(org, issuer: "https://another.example.test")).Code);
        Assert.NotEqual(0, (await Add(org, subject: "synthetic-third-admin")).Code);
        Assert.NotEqual(0, (await Add(org, subject: Initial)).Code);
        Assert.Equal((2L, 2L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Missing_inactive_legacy_pending_or_suspended_org_denied()
    {
        var unknown = Guid.NewGuid();
        Assert.NotEqual(0, (await Add(unknown)).Code);
        var noAdmin = await Seed();
        Assert.NotEqual(0, (await Add(noAdmin)).Code);
        var pending = await Seed(activated: false);
        Assert.Equal(0, (await Bootstrap(pending)).Code);
        Assert.NotEqual(0, (await Add(pending)).Code);
        var suspended = await Seed(suspended: true);
        Assert.NotEqual(0, (await Add(suspended)).Code);
        var inactive = await Seed();
        Assert.Equal(0, (await Bootstrap(inactive)).Code);
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                UPDATE platform.organization_memberships SET is_active=FALSE
                WHERE organization_id=@org AND role='Admin'
                """, conn);
            cmd.Parameters.AddWithValue("org", inactive);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(inactive)).Code);
        var legacy = await Seed();
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id, subject, role, is_active, identity_issuer)
                VALUES (@org, 'unbound-admin', 'Admin', TRUE, NULL)
                """, conn);
            cmd.Parameters.AddWithValue("org", legacy);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(legacy)).Code);
        Assert.Equal((0L, 0L, 0L, 0L), await Counts(unknown));
        Assert.Equal((0L, 0L, 0L, 0L), await Counts(noAdmin));
        Assert.Equal((1L, 1L, 0L, 1L), await Counts(pending));
        Assert.Equal((1L, 0L, 0L, 1L), await Counts(inactive));
    }

    [Fact]
    public async Task Invalid_inputs_existing_other_role_and_runtime_sql_are_denied()
    {
        var org = await Seed();
        Assert.Equal(0, (await Bootstrap(org)).Code);
        foreach (var attempt in new[]
        {
            Add(org, issuer: "http://identity.example.test"),
            Add(org, issuer: "https://evil.test@identity.example.test"),
            Add(org, subject: " synthetic-admin "),
            Add(org, subject: "synthetic-admin\nnewline"),
            Add(org, ticket: null),
            Add(org, reviewer: null),
            Add(org, ticket: "bad ticket"),
            Add(org, subject: "x'); DROP TABLE platform.organizations; --")
        })
        {
            var denied = await attempt;
            Assert.NotEqual(0, denied.Code);
        }
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id,subject,role,is_active,identity_issuer)
                VALUES (@org,@subject,'Reader',TRUE,@issuer)
                """, conn);
            cmd.Parameters.AddWithValue("org", org);
            cmd.Parameters.AddWithValue("subject", Second);
            cmd.Parameters.AddWithValue("issuer", Issuer);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(org)).Code);
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted runtime PostgreSQL credential required.");
        Assert.NotEqual(0, (await Add(org, connection: runtime)).Code);
        Assert.Equal((1L, 1L, 0L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Concurrent_owner_attempts_allow_single_binding_per_ticket()
    {
        var org = await Seed();
        Assert.Equal(0, (await Bootstrap(org)).Code);
        var parallel = await Task.WhenAll(
            Add(org, subject: "candidate-a"),
            Add(org, subject: "candidate-b"));
        Assert.Single(parallel.Where(result => result.Code == 0));
        Assert.Equal((2L, 2L, 1L, 1L), await Counts(org));

        var another = await Seed();
        Assert.Equal(0, (await Bootstrap(another)).Code);
        var identical = await Task.WhenAll(Add(another), Add(another));
        Assert.All(identical, result => Assert.Equal(0, result.Code));
        Assert.Equal((2L, 2L, 1L, 1L), await Counts(another));
    }
}

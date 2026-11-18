using System.Diagnostics;
using System.Net;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first owner-only Admin revocation with real disposable PostgreSQL and
/// a locally signed RS256 OIDC API token; no external identity or Azure calls.
/// </summary>
public sealed class AdminRevocationTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private const string Issuer = OidcApiFactory.Issuer;
    private const string First = "admin-revoke-first";
    private const string Second = "admin-revoke-second";
    private const string Third = "admin-revoke-third";
    private const string Ticket = "CHANGE-2026-00081";
    private const string Reason = "operator-departure";

    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL connection required.");

    private static string Root()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return dir.FullName;
        throw new InvalidOperationException("Repository root not found.");
    }

    private static async Task<Guid> Seed(bool activated = true, bool suspended = false,
        params string[] admins)
    {
        var org = Guid.NewGuid();
        await using var conn = new NpgsqlConnection(Owner);
        await conn.OpenAsync();
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name, is_activated, is_suspended)
            VALUES (@org, 'Comune sintetico revoca Admin', @activated, @suspended)
            """, conn))
        {
            insert.Parameters.AddWithValue("org", org);
            insert.Parameters.AddWithValue("activated", activated);
            insert.Parameters.AddWithValue("suspended", suspended);
            await insert.ExecuteNonQueryAsync();
        }
        foreach (var subject in admins)
        {
            await using var insert = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id, subject, role, is_active, identity_issuer)
                VALUES (@org, @sub, 'Admin', TRUE, @issuer)
                """, conn);
            insert.Parameters.AddWithValue("org", org);
            insert.Parameters.AddWithValue("sub", subject);
            insert.Parameters.AddWithValue("issuer", Issuer);
            await insert.ExecuteNonQueryAsync();
        }
        return org;
    }

    private static async Task<(int Code, string Output)> Revoke(Guid org,
        string? subject = Second, string? issuer = Issuer,
        string? ticket = Ticket, string? reviewer = "independent-reviewer",
        string? reason = Reason, string? connection = null,
        bool logStatements = false)
    {
        var script = Path.Combine(Root(), "scripts/postgres/revoke-admin.sql");
        Assert.True(File.Exists(script), "RED: owner-only Admin revocation script missing.");
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var arg in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", db.Host, "-p", db.Port.ToString(),
            "-U", db.Username, "-d", db.Database, "-f", script
        }) start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = db.Password;
        if (logStatements)
            start.Environment["PGOPTIONS"] =
                "-c log_statement=all -c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";
        void Set(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Set("COMUNI_REVOKE_ADMIN_ORGANIZATION_ID", org.ToString("D"));
        Set("COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER", issuer);
        Set("COMUNI_REVOKE_ADMIN_SUBJECT", subject);
        Set("COMUNI_REVOKE_ADMIN_CHANGE_TICKET", ticket);
        Set("COMUNI_REVOKE_ADMIN_APPROVER", reviewer);
        Set("COMUNI_REVOKE_ADMIN_REASON_CODE", reason);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("psql unavailable");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(long ActiveAdmins, long DisabledAdmins, long Revocations)> State(Guid org)
    {
        await using var conn = new NpgsqlConnection(Owner);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM platform.organization_memberships
                 WHERE organization_id=@org AND role='Admin' AND is_active),
                (SELECT count(*) FROM platform.organization_memberships
                 WHERE organization_id=@org AND role='Admin' AND NOT is_active),
                (SELECT count(*) FROM platform.audit_events
                 WHERE organization_id=@org AND action='platform.membership.admin.revoked')
            """, conn);
        cmd.Parameters.AddWithValue("org", org);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2));
    }

    [Fact]
    public async Task Revoke_is_audited_atomic_and_exact_same_ticket_retry_is_noop()
    {
        var org = await Seed(admins: [First, Second]);
        var first = await Revoke(org);
        Assert.Equal(0, first.Code);
        foreach (var privateValue in new[] { Issuer, Second, Ticket, Reason, org.ToString("D") })
            Assert.DoesNotContain(privateValue, first.Output);
        Assert.Equal((1L, 1L, 1L), await State(org));
        Assert.Equal(0, (await Revoke(org)).Code);
        Assert.Equal((1L, 1L, 1L), await State(org));

        await using var conn = new NpgsqlConnection(Owner);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT actor_subject, resource_type, correlation_id, resource_id
            FROM platform.audit_events
            WHERE organization_id=@org AND action='platform.membership.admin.revoked'
            """, conn);
        cmd.Parameters.AddWithValue("org", org);
        await using var row = await cmd.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.StartsWith("db-owner:", row.GetString(0));
        Assert.Equal("platform.membership", row.GetString(1));
        Assert.Equal("admin-revoke:" + Ticket, row.GetString(2));
        Assert.NotEqual(Guid.Empty, row.GetGuid(3));
        Assert.False(await row.ReadAsync());
    }

    [Fact]
    public async Task Reused_original_oidc_token_loses_all_admin_access_on_next_request()
    {
        var org = await Seed(admins: [First, Second]);
        using var target = factory.Authenticated(factory.Token(
            subject: Second, organizationId: org.ToString("D")));
        using var survivor = factory.Authenticated(factory.Token(
            subject: First, organizationId: org.ToString("D")));
        Assert.Equal(HttpStatusCode.OK, (await target.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await target.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(0, (await Revoke(org)).Code);
        // Exactly the same signed RS256 access token stays in the HttpClient.
        Assert.Equal(HttpStatusCode.Forbidden, (await target.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await target.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await target.GetAsync("/api/v1/admin/memberships")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await survivor.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await survivor.GetAsync("/api/v1/admin/modules")).StatusCode);
    }

    [Fact]
    public async Task Last_admin_must_not_be_revoked_even_with_other_non_admin_members()
    {
        var org = await Seed(admins: [First]);
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var add = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                  (organization_id, subject, role, is_active, identity_issuer)
                VALUES (@org, 'reader-not-admin', 'Reader', TRUE, @issuer)
                """, conn);
            add.Parameters.AddWithValue("org", org);
            add.Parameters.AddWithValue("issuer", Issuer);
            await add.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Revoke(org, subject: First)).Code);
        Assert.Equal((1L, 0L, 0L), await State(org));
    }

    [Fact]
    public async Task Concurrent_different_revocations_cannot_leave_zero_active_admins()
    {
        var org = await Seed(admins: [First, Second]);
        var results = await Task.WhenAll(
            Revoke(org, subject: First),
            Revoke(org, subject: Second));
        Assert.Single(results, result => result.Code == 0);
        Assert.Equal((1L, 1L, 1L), await State(org));
    }

    [Fact]
    public async Task Concurrent_identical_revocations_are_idempotent()
    {
        var org = await Seed(admins: [First, Second]);
        var results = await Task.WhenAll(Revoke(org), Revoke(org));
        Assert.All(results, result => Assert.Equal(0, result.Code));
        Assert.Equal((1L, 1L, 1L), await State(org));
    }

    [Fact]
    public async Task Different_issuer_ticket_or_target_cannot_replay_approval()
    {
        var org = await Seed(admins: [First, Second, Third]);
        Assert.Equal(0, (await Revoke(org)).Code);
        Assert.NotEqual(0, (await Revoke(org, subject: Third)).Code);
        Assert.NotEqual(0, (await Revoke(org, ticket: "CHANGE-2026-OTHER81")).Code);
        Assert.NotEqual(0, (await Revoke(org, issuer: "https://other.example.test/")).Code);
        Assert.Equal((2L, 1L, 1L), await State(org));
    }

    [Fact]
    public async Task Missing_created_suspended_inactive_legacy_or_wrong_issuer_is_denied()
    {
        Assert.NotEqual(0, (await Revoke(Guid.NewGuid())).Code);
        var pending = await Seed(activated: false, admins: [First, Second]);
        var suspended = await Seed(suspended: true, admins: [First, Second]);
        Assert.NotEqual(0, (await Revoke(pending)).Code);
        Assert.NotEqual(0, (await Revoke(suspended)).Code);
        var inactive = await Seed(admins: [First, Second]);
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE platform.organization_memberships SET is_active=FALSE
                WHERE organization_id=@org AND subject=@sub AND role='Admin'
                """, conn);
            update.Parameters.AddWithValue("org", inactive);
            update.Parameters.AddWithValue("sub", Second);
            await update.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Revoke(inactive)).Code);
        var legacy = await Seed(admins: [First, Second]);
        await using (var conn = new NpgsqlConnection(Owner))
        {
            await conn.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE platform.organization_memberships SET identity_issuer=NULL
                WHERE organization_id=@org AND subject=@sub AND role='Admin'
                """, conn);
            update.Parameters.AddWithValue("org", legacy);
            update.Parameters.AddWithValue("sub", Second);
            await update.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Revoke(legacy)).Code);
        Assert.Equal((2L, 0L, 0L), await State(legacy));
        Assert.Equal((1L, 1L, 0L), await State(inactive));
    }

    [Fact]
    public async Task Input_spoofing_runtime_login_and_cross_tenant_are_denied()
    {
        var org = await Seed(admins: [First, Second]);
        foreach (var denial in new[] {
            Revoke(org, issuer: "http://not-https.example.test"),
            Revoke(org, issuer: "https://evil.test@identity.example.test"),
            Revoke(org, subject: " second "),
            Revoke(org, subject: "bad\nnewline"),
            Revoke(org, ticket: null),
            Revoke(org, reviewer: null),
            Revoke(org, reason: null),
            Revoke(org, ticket: "bad ticket"),
            Revoke(org, reason: "operator'; DROP TABLE platform.organizations;--"),
            Revoke(org, subject: "unassigned-subject")
        })
        {
            Assert.NotEqual(0, (await denial).Code);
        }
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted PostgreSQL login required.");
        Assert.NotEqual(0, (await Revoke(org, connection: runtime)).Code);

        var other = await Seed(admins: [First, Second]);
        Assert.Equal(0, (await Revoke(org)).Code);
        Assert.Equal((1L, 1L, 1L), await State(org));
        Assert.Equal((2L, 0L, 0L), await State(other));
        using var otherTenant = factory.Authenticated(factory.Token(
            subject: Second, organizationId: other.ToString("D")));
        Assert.Equal(HttpStatusCode.OK, (await otherTenant.GetAsync("/api/v1/context")).StatusCode);
    }
    [Fact]
    public async Task Revocation_script_must_not_inline_issuer_or_subject_as_SQL_literals()
    {
        var source = await File.ReadAllTextAsync(
            Path.Combine(Root(), "scripts", "postgres", "revoke-admin.sql"));
        Assert.DoesNotContain(":'revoke_subject'", source);
        Assert.DoesNotContain(":'revoke_issuer'", source);
    }

    [Fact]
    public async Task Revocation_issuer_and_subject_are_absent_from_real_Postgres_statement_logs()
    {
        // Distinct canaries per invocation; never print logs or the canaries on
        // failure, even when logging is deliberately maximized in PostgreSQL.
        var org = await Seed(admins: [First, Second]);
        var subject = "synthetic-revoke-private-" + Guid.NewGuid().ToString("N");
        var issuer = "https://revoke-" + Guid.NewGuid().ToString("N") + ".example.test";
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE platform.organization_memberships
                SET subject=@subject, identity_issuer=@issuer
                WHERE organization_id=@org AND role='Admin' AND subject=@original
                """, db);
            update.Parameters.AddWithValue("org", org);
            update.Parameters.AddWithValue("subject", subject);
            update.Parameters.AddWithValue("issuer", issuer);
            update.Parameters.AddWithValue("original", Second);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }

        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");
        var result = await Revoke(org, subject: subject, issuer: issuer, logStatements: true);
        Assert.Equal(0, result.Code);
        Assert.False(result.Output.Contains(subject, StringComparison.Ordinal)
                     || result.Output.Contains(issuer, StringComparison.Ordinal),
            "psql output included synthetic private identity.");
        Assert.Equal((1L, 1L, 1L), await State(org));

        using var ps = new Process();
        ps.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] {
            "ps", "--filter", "ancestor=postgres:17-alpine", "--format", "{{.ID}}"
        })
            ps.StartInfo.ArgumentList.Add(arg);
        try
        {
            ps.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI must expose PostgreSQL 17 server logs.");
            return;
        }

        var ids = (await ps.StandardOutput.ReadToEndAsync()).Trim();
        _ = await ps.StandardError.ReadToEndAsync();
        await ps.WaitForExitAsync();
        if (ps.ExitCode != 0 || string.IsNullOrWhiteSpace(ids))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI PostgreSQL server log is mandatory.");
            return;
        }
        Assert.DoesNotContain('\n', ids);

        using var logs = new Process();
        logs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "logs", "--since", since, ids })
            logs.StartInfo.ArgumentList.Add(arg);
        logs.Start();
        var stdout = logs.StandardOutput.ReadToEndAsync();
        var stderr = logs.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await logs.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, logs.ExitCode);
        var serverLog = await stdout + await stderr;
        Assert.Contains("statement: COPY", serverLog);
        Assert.False(serverLog.Contains(subject, StringComparison.Ordinal)
                     || serverLog.Contains(issuer, StringComparison.Ordinal),
            "PostgreSQL statement log contained private synthetic OIDC identity; raw logs withheld.");
    }

}

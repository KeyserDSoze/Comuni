using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Approved owner-only platform operator enrollment/revocation contracts against
/// disposable PostgreSQL 17. All issuers, subjects and tickets are synthetic.
/// </summary>
public sealed class PlatformOperatorEnrollmentTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION required.");

    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_RUNTIME_DATABASE_CONNECTION required.");

    private static string Script
    {
        get
        {
            for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
                if (File.Exists(Path.Combine(d.FullName, "AGENTS.md")))
                    return Path.Combine(d.FullName, "scripts", "postgres", "manage-platform-operator.sql");
            throw new InvalidOperationException("Repository root not found.");
        }
    }

    private static async Task<(int Code, string Output)> ChangeAsync(
        string? issuer, string? subject, string? action = "enroll",
        string? ticket = "CHANGE-2026-00035", string? approver = "independent-reviewer",
        string? connectionOverride = null)
    {
        Assert.True(File.Exists(Script), "Owner-only platform operator management script is missing.");
        var b = new NpgsqlConnectionStringBuilder(connectionOverride ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[] { "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", b.Host, "-p", b.Port.ToString(), "-U", b.Username,
            "-d", b.Database, "-f", Script })
            start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = b.Password;
        void Set(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Set("COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER", issuer);
        Set("COMUNI_PLATFORM_OPERATOR_SUBJECT", subject);
        Set("COMUNI_PLATFORM_OPERATOR_ACTION", action);
        Set("COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET", ticket);
        Set("COMUNI_PLATFORM_OPERATOR_APPROVER", approver);
        using var p = Process.Start(start)
            ?? throw new InvalidOperationException("Could not launch psql.");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await p.WaitForExitAsync(timeout.Token);
        return (p.ExitCode, await stdout + await stderr);
    }

    private static async Task<(long Operators, bool? Active, long Enrolls,
        long Revokes, long Reactivations, Guid? Id)> StateAsync(string issuer, string subject)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT
                (SELECT COUNT(*) FROM platform.platform_operators
                 WHERE identity_issuer = @iss AND subject = @sub),
                (SELECT is_active FROM platform.platform_operators
                 WHERE identity_issuer = @iss AND subject = @sub),
                (SELECT COUNT(*) FROM platform.platform_operator_audit_events
                 WHERE resource_id = (SELECT operator_id FROM platform.platform_operators
                     WHERE identity_issuer = @iss AND subject = @sub)
                   AND action = 'platform.operator.enrolled'),
                (SELECT COUNT(*) FROM platform.platform_operator_audit_events
                 WHERE resource_id = (SELECT operator_id FROM platform.platform_operators
                     WHERE identity_issuer = @iss AND subject = @sub)
                   AND action = 'platform.operator.revoked'),
                (SELECT COUNT(*) FROM platform.platform_operator_audit_events
                 WHERE resource_id = (SELECT operator_id FROM platform.platform_operators
                     WHERE identity_issuer = @iss AND subject = @sub)
                   AND action = 'platform.operator.reactivated'),
                (SELECT operator_id FROM platform.platform_operators
                 WHERE identity_issuer = @iss AND subject = @sub)
            """, db);
        command.Parameters.AddWithValue("iss", issuer);
        command.Parameters.AddWithValue("sub", subject);
        await using var row = await command.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetInt64(0), row.IsDBNull(1) ? null : row.GetBoolean(1),
            row.GetInt64(2), row.GetInt64(3), row.GetInt64(4),
            row.IsDBNull(5) ? null : row.GetGuid(5));
    }

    [Fact]
    public async Task Approved_enrollment_and_revoke_are_atomic_and_take_effect_on_next_api_request()
    {
        var subject = "approved-platform-" + Guid.NewGuid().ToString("N");
        var issuer = OidcApiFactory.Issuer;
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/platform/session")).StatusCode);

        var enroll = await ChangeAsync(issuer, subject);
        Assert.Equal(0, enroll.Code);
        Assert.DoesNotContain(issuer, enroll.Output);
        Assert.DoesNotContain(subject, enroll.Output);
        Assert.DoesNotContain("CHANGE-2026-00035", enroll.Output);
        var state = await StateAsync(issuer, subject);
        Assert.Equal((1L, true, 1L, 0L, 0L), (state.Operators, state.Active,
            state.Enrolls, state.Revokes, state.Reactivations));
        Assert.NotNull(state.Id);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/platform/session")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/context")).StatusCode);

        var revoke = await ChangeAsync(issuer, subject, action: "revoke");
        Assert.Equal(0, revoke.Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/platform/session")).StatusCode);
        var stateAfter = await StateAsync(issuer, subject);
        Assert.Equal((1L, false, 1L, 1L, 0L), (stateAfter.Operators, stateAfter.Active,
            stateAfter.Enrolls, stateAfter.Revokes, stateAfter.Reactivations));
        Assert.Equal(state.Id, stateAfter.Id);

        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT actor_subject, action, resource_type, resource_id, correlation_id
            FROM platform.platform_operator_audit_events WHERE resource_id = @operator
            ORDER BY occurred_at, id
            """, db);
        query.Parameters.AddWithValue("operator", state.Id!.Value);
        await using var rows = await query.ExecuteReaderAsync();
        var actions = new List<string>();
        while (await rows.ReadAsync())
        {
            Assert.StartsWith("db-owner:", rows.GetString(0));
            actions.Add(rows.GetString(1));
            Assert.Equal("platform.operator", rows.GetString(2));
            Assert.Equal(state.Id, rows.GetGuid(3));
            Assert.Equal("operator:CHANGE-2026-00035", rows.GetString(4));
            Assert.DoesNotContain(subject, string.Join("|", Enumerable.Range(0, 5)
                .Select(i => rows.GetValue(i).ToString())));
            Assert.DoesNotContain(issuer, string.Join("|", Enumerable.Range(0, 5)
                .Select(i => rows.GetValue(i).ToString())));
        }
        Assert.Equal(new[] { "platform.operator.enrolled", "platform.operator.revoked" }, actions);
    }

    [Fact]
    public async Task Concurrent_enrollment_and_retries_generate_one_event_per_effective_transition()
    {
        var issuer = OidcApiFactory.Issuer;
        var subject = "concurrent-platform-" + Guid.NewGuid().ToString("N");
        var first = await Task.WhenAll(
            ChangeAsync(issuer, subject), ChangeAsync(issuer, subject));
        Assert.All(first, x => Assert.Equal(0, x.Code));
        Assert.Equal(0, (await ChangeAsync(issuer, subject)).Code);
        var one = await StateAsync(issuer, subject);
        Assert.Equal((1L, true, 1L, 0L, 0L), (one.Operators, one.Active,
            one.Enrolls, one.Revokes, one.Reactivations));

        var revocations = await Task.WhenAll(
            ChangeAsync(issuer, subject, "revoke"),
            ChangeAsync(issuer, subject, "revoke"));
        Assert.All(revocations, x => Assert.Equal(0, x.Code));
        Assert.Equal(0, (await ChangeAsync(issuer, subject, "revoke")).Code);

        var after = await StateAsync(issuer, subject);
        Assert.Equal((1L, false, 1L, 1L, 0L), (after.Operators, after.Active,
            after.Enrolls, after.Revokes, after.Reactivations));

        // Separate approval/change is required operationally for any re-enrollment.
        Assert.Equal(0, (await ChangeAsync(issuer, subject,
            ticket: "CHANGE-2026-REAPPROVE")).Code);
        var reactivated = await StateAsync(issuer, subject);
        Assert.Equal((1L, true, 1L, 1L, 1L), (reactivated.Operators,
            reactivated.Active, reactivated.Enrolls, reactivated.Revokes,
            reactivated.Reactivations));
        Assert.Equal(one.Id, reactivated.Id);
    }

    [Fact]
    public async Task Missing_invalid_issuer_subject_action_and_approvals_cannot_grant_operator()
    {
        var issuer = OidcApiFactory.Issuer;
        var subject = "invalid-platform-" + Guid.NewGuid().ToString("N");
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, "revoke")).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, action: null)).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, "delete")).Code);
        Assert.NotEqual(0, (await ChangeAsync(null, subject)).Code);
        Assert.NotEqual(0, (await ChangeAsync("http://issuer.example.test", subject)).Code);
        Assert.NotEqual(0, (await ChangeAsync("https://evil.test@issuer.example.test", subject)).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, null)).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, "")).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, " signed-in-admin ")).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, "test\nctrl")).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, new string('x', 161))).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, ticket: null)).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, ticket: "bad ticket")).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, approver: null)).Code);
        Assert.NotEqual(0, (await ChangeAsync(issuer, subject, approver: "x")).Code);
        var state = await StateAsync(issuer, subject);
        Assert.Equal((0L, null, 0L, 0L, 0L), (state.Operators, state.Active,
            state.Enrolls, state.Revokes, state.Reactivations));
    }

    [Fact]
    public async Task Quoted_subject_is_a_literal_not_SQL_and_does_not_appear_in_logs()
    {
        var issuer = OidcApiFactory.Issuer;
        var subject = "malicious'); DROP TABLE platform.platform_operators;--";
        var result = await ChangeAsync(issuer, subject);
        Assert.Equal(0, result.Code);
        Assert.DoesNotContain(subject, result.Output);
        Assert.Equal(1L, (await StateAsync(issuer, subject)).Operators);
    }

    [Fact]
    public async Task Global_audit_is_append_only_and_runtime_login_has_no_direct_privileges()
    {
        var issuer = OidcApiFactory.Issuer;
        var subject = "audit-platform-" + Guid.NewGuid().ToString("N");
        Assert.Equal(0, (await ChangeAsync(issuer, subject)).Code);
        var id = (await StateAsync(issuer, subject)).Id!.Value;
        await using var owner = new NpgsqlConnection(Owner);
        await owner.OpenAsync();
        foreach (var statement in new[]
        {
            "UPDATE platform.platform_operator_audit_events SET action = 'forged' WHERE resource_id = @id",
            "DELETE FROM platform.platform_operator_audit_events WHERE resource_id = @id",
            "TRUNCATE TABLE platform.platform_operator_audit_events"
        })
        {
            await using var cmd = new NpgsqlCommand(statement, owner);
            if (!statement.StartsWith("TRUNCATE")) cmd.Parameters.AddWithValue("id", id);
            var error = await Assert.ThrowsAsync<PostgresException>(
                () => cmd.ExecuteNonQueryAsync());
            Assert.Equal("55000", error.SqlState);
        }

        await using var runtime = new NpgsqlConnection(Runtime);
        await runtime.OpenAsync();
        await using var probe = new NpgsqlCommand("""
            SELECT
              has_table_privilege(current_user, 'platform.platform_operators', 'SELECT'),
              has_any_column_privilege(current_user, 'platform.platform_operators', 'INSERT'),
              has_any_column_privilege(current_user, 'platform.platform_operators', 'UPDATE'),
              has_table_privilege(current_user, 'platform.platform_operators', 'DELETE'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'SELECT'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'INSERT'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'UPDATE'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'DELETE'),
              has_function_privilege(current_user,
                'platform.is_active_platform_operator(text,text)', 'EXECUTE')
            """, runtime);
        await using var rows = await probe.ExecuteReaderAsync();
        Assert.True(await rows.ReadAsync());
        for (var i = 0; i < 8; i++) Assert.False(rows.GetBoolean(i));
        Assert.True(rows.GetBoolean(8));
    }

    [Fact]
    public async Task Restricted_runtime_cannot_manage_platform_operators_even_with_fake_approval()
    {
        var issuer = OidcApiFactory.Issuer;
        var subject = "runtime-denied-" + Guid.NewGuid().ToString("N");
        var denied = await ChangeAsync(issuer, subject, connectionOverride: Runtime);
        Assert.NotEqual(0, denied.Code);
        Assert.Equal(0L, (await StateAsync(issuer, subject)).Operators);
    }
}

using System.Diagnostics;
using System.Net;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Owner-only onboarding tests against disposable PostgreSQL and psql.
/// Does not call Azure or an external identity provider.
/// </summary>
public sealed class OrganizationRegistrationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static string OwnerConnection => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL required.");

    private static string Script(string filename)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "AGENTS.md")))
                return Path.Combine(d.FullName, "scripts", "postgres", filename);
        throw new InvalidOperationException("Repository root not found.");
    }

    private static async Task<(int Code, string Output)> RegisterAsync(
        string organization, string? name = "Comune Sintetico di Prova",
        string? ticket = "CHANGE-2026-00043", string? reviewer = "independent-reviewer",
        string? connectionOverride = null, bool logStatements = false)
    {
        var path = Script("register-organization.sql");
        Assert.True(File.Exists(path), "Owner-only organization registration script missing (RED).");
        var database = new NpgsqlConnectionStringBuilder(connectionOverride ?? OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            // The static \\copy FROM PROGRAM helper must resolve from trusted repo root.
            WorkingDirectory = Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(path)!, "..", "..")),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", database.Host,
            "-p", database.Port.ToString(), "-U", database.Username,
            "-d", database.Database, "-f", path
        }) start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = database.Password;
        if (logStatements)
            start.Environment["PGOPTIONS"] =
                "-c log_statement=all -c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";
        start.Environment["COMUNI_REGISTER_ORGANIZATION_ID"] = organization;
        void Optional(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Optional("COMUNI_REGISTER_ORGANIZATION_NAME", name);
        Optional("COMUNI_REGISTER_CHANGE_TICKET", ticket);
        Optional("COMUNI_REGISTER_APPROVER", reviewer);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("psql unavailable.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(long Organizations, long Modules, long EnabledModules,
        long Memberships, long Audit, string? Name, bool? Suspended, string? Correlation)> StateAsync(Guid id)
    {
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM platform.organizations WHERE id=@id),
                (SELECT count(*) FROM platform.organization_modules WHERE organization_id=@id AND module_key='protocol'),
                (SELECT count(*) FROM platform.organization_modules WHERE organization_id=@id AND module_key='protocol' AND enabled),
                (SELECT count(*) FROM platform.organization_memberships WHERE organization_id=@id),
                (SELECT count(*) FROM platform.audit_events WHERE organization_id=@id AND action='platform.organization.registered'),
                (SELECT name FROM platform.organizations WHERE id=@id),
                (SELECT is_suspended FROM platform.organizations WHERE id=@id),
                (SELECT correlation_id FROM platform.audit_events WHERE organization_id=@id AND action='platform.organization.registered' LIMIT 1)
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var rd = await cmd.ExecuteReaderAsync();
        Assert.True(await rd.ReadAsync());
        return (rd.GetInt64(0), rd.GetInt64(1), rd.GetInt64(2), rd.GetInt64(3),
            rd.GetInt64(4), rd.IsDBNull(5) ? null : rd.GetString(5),
            rd.IsDBNull(6) ? null : rd.GetBoolean(6), rd.IsDBNull(7) ? null : rd.GetString(7));
    }

    [Fact]
    public async Task Owner_registers_exactly_one_pending_empty_tenant_with_protocol_disabled_and_audit()
    {
        var id = Guid.NewGuid();
        var result = await RegisterAsync(id.ToString("D"));
        Assert.Equal(0, result.Code);
        Assert.DoesNotContain("Comune Sintetico di Prova", result.Output);
        Assert.DoesNotContain("CHANGE-2026-00043", result.Output);
        Assert.DoesNotContain(id.ToString(), result.Output);
        var state = await StateAsync(id);
        Assert.Equal((1L, 1L, 0L, 0L, 1L), (state.Organizations, state.Modules,
            state.EnabledModules, state.Memberships, state.Audit));
        Assert.Equal("Comune Sintetico di Prova", state.Name);
        Assert.False(state.Suspended);
        Assert.Equal("register:CHANGE-2026-00043", state.Correlation);

        using var unassigned = factory.ClientFor(id.ToString(), "Admin", "not-onboarded");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await unassigned.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await unassigned.GetAsync("/api/v1/context")).StatusCode);

        var repeat = await RegisterAsync(id.ToString("D"));
        Assert.Equal(0, repeat.Code);
        Assert.Equal((1L, 1L, 0L, 0L, 1L),
            ((await StateAsync(id)).Organizations, (await StateAsync(id)).Modules,
             (await StateAsync(id)).EnabledModules, (await StateAsync(id)).Memberships,
             (await StateAsync(id)).Audit));
    }

    [Fact]
    public async Task Different_name_or_ticket_or_preexisting_unregistered_tenant_is_not_adopted()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await RegisterAsync(id.ToString())).Code);
        Assert.NotEqual(0, (await RegisterAsync(id.ToString(),
            name: "Un altro Comune sintetico")).Code);
        Assert.NotEqual(0, (await RegisterAsync(id.ToString(),
            ticket: "CHANGE-2026-OTHER")).Code);
        var existing = await StateAsync(id);
        Assert.Equal("Comune Sintetico di Prova", existing.Name);
        Assert.Equal(1L, existing.Audit);
        Assert.Equal(0L, existing.EnabledModules);

        var old = Guid.NewGuid();
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var insert = new NpgsqlCommand(
            "INSERT INTO platform.organizations(id,name) VALUES (@id,'Comune Sintetico di Prova')", db);
        insert.Parameters.AddWithValue("id", old);
        await insert.ExecuteNonQueryAsync();
        Assert.NotEqual(0, (await RegisterAsync(old.ToString())).Code);
        Assert.Equal(0L, (await StateAsync(old)).Audit);
    }

    [Fact]
    public async Task Invalid_inputs_are_refused_atomically_and_without_echoing_private_values()
    {
        foreach (var bad in new[]
        {
            (Name: (string?)null, Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)" ", Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)" XX ", Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)"Comune\nInjected", Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)new string('x', 201), Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)"Comune'); DROP TABLE platform.organizations; --", Ticket: (string?)null, Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)"Comune Privato", Ticket: (string?)"bad ticket", Reviewer: (string?)"independent-reviewer"),
            (Name: (string?)"Comune Privato", Ticket: (string?)"CHANGE-2026-00043", Reviewer: (string?)null)
        })
        {
            var id = Guid.NewGuid();
            var result = await RegisterAsync(id.ToString(), bad.Name, bad.Ticket, bad.Reviewer);
            Assert.NotEqual(0, result.Code);
            Assert.Equal((0L, 0L, 0L, 0L, 0L),
                ((await StateAsync(id)).Organizations, (await StateAsync(id)).Modules,
                 (await StateAsync(id)).EnabledModules, (await StateAsync(id)).Memberships,
                 (await StateAsync(id)).Audit));
            Assert.DoesNotContain("Comune Privato", result.Output);
            Assert.DoesNotContain("CHANGE-2026-00043", result.Output);
        }
        foreach (var input in new[] { "not-uuid", Guid.Empty.ToString(), "11111111-1111-1111-1111-111111111111' OR TRUE --" })
            Assert.NotEqual(0, (await RegisterAsync(input)).Code);
    }

    [Fact]
    public async Task Restricted_runtime_login_cannot_create_an_organization()
    {
        var id = Guid.NewGuid();
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted login missing.");
        Assert.NotEqual(0, (await RegisterAsync(id.ToString(), connectionOverride: runtime)).Code);
        var state = await StateAsync(id);
        Assert.Equal(0L, state.Organizations);
        Assert.Equal(0L, state.Audit);
    }

    [Fact]
    public async Task Concurrent_registration_with_same_identifier_is_idempotent_without_duplicates()
    {
        var id = Guid.NewGuid();
        var responses = await Task.WhenAll(
            RegisterAsync(id.ToString()), RegisterAsync(id.ToString()));
        Assert.All(responses, x => Assert.Equal(0, x.Code));
        var state = await StateAsync(id);
        Assert.Equal((1L, 1L, 0L, 0L, 1L), (state.Organizations, state.Modules,
            state.EnabledModules, state.Memberships, state.Audit));
    }

    [Fact]
    public async Task Registration_precedes_separate_owner_verified_first_Oidc_Admin_bootstrap()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await RegisterAsync(id.ToString(),
            name: "Comune d'Acqua")).Code);
        var database = new NpgsqlConnectionStringBuilder(OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            // Bootstrap private COPY resolves a fixed helper from repo root.
            WorkingDirectory = Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(Script("bootstrap-initial-admin.sql"))!, "..", "..")),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", database.Host,
            "-p", database.Port.ToString(), "-U", database.Username,
            "-d", database.Database, "-f", Script("bootstrap-initial-admin.sql")
        }) start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = database.Password;
        start.Environment["COMUNI_BOOTSTRAP_ORGANIZATION_ID"] = id.ToString();
        start.Environment["COMUNI_BOOTSTRAP_IDENTITY_ISSUER"] = "https://identity.example.test/tenant/v2.0";
        start.Environment["COMUNI_BOOTSTRAP_SUBJECT"] = "municipal-first-admin";
        start.Environment["COMUNI_BOOTSTRAP_CHANGE_TICKET"] = "CHANGE-2026-ADMIN43";
        start.Environment["COMUNI_BOOTSTRAP_APPROVER"] = "independent-reviewer";
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("psql could not bootstrap Admin");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        var output = await stdout + await stderr;
        Assert.Equal(0, process.ExitCode);
        Assert.DoesNotContain("municipal-first-admin", output);
        Assert.DoesNotContain("identity.example.test", output);

        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT COUNT(*), COUNT(*) FILTER (WHERE identity_issuer =
                'https://identity.example.test/tenant/v2.0' AND is_active)
            FROM platform.organization_memberships
            WHERE organization_id=@id AND role='Admin'
            """, db);
        query.Parameters.AddWithValue("id", id);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.Equal(1, row.GetInt64(0));
        Assert.Equal(1, row.GetInt64(1));
        var state = await StateAsync(id);
        Assert.Equal(1L, state.Organizations);
        Assert.Equal(0L, state.EnabledModules);
        Assert.Equal(1L, state.Audit);
        Assert.Equal("Comune d'Acqua", state.Name);
    }

    [Fact]
    public async Task Suspended_tenant_retry_does_not_reactivate_or_reenable_protocol()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await RegisterAsync(id.ToString())).Code);
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var change = new NpgsqlCommand(
            // Simulate a legitimately activated-and-then-suspended organization.
            // A pending municipality cannot be suspended directly: SQL
            // lifecycle constraint now enforces created -> active -> suspended.
            "UPDATE platform.organizations SET is_activated=TRUE,is_suspended=TRUE WHERE id=@id", db);
        change.Parameters.AddWithValue("id", id);
        await change.ExecuteNonQueryAsync();

        Assert.Equal(0, (await RegisterAsync(id.ToString())).Code);
        var state = await StateAsync(id);
        Assert.True(state.Suspended);
        Assert.Equal(0L, state.EnabledModules);
        Assert.Equal(1L, state.Audit);
    }

    [Fact]
    public async Task Registration_SQL_does_not_inline_any_owner_private_input()
    {
        var sql = await File.ReadAllTextAsync(Script("register-organization.sql"));
        foreach (var name in new[] {
            "register_org", "register_name", "register_ticket", "register_approver"
        })
            Assert.DoesNotContain(":'" + name + "'", sql);
        Assert.Contains("FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py register-organization'", sql);
    }

    [Fact]
    public async Task Owner_registration_private_name_ticket_reviewer_are_absent_from_real_Postgres_statement_logs()
    {
        // All markers are synthetic. Never print PostgreSQL logs or the markers
        // on failure. CI must fail if real PostgreSQL 17 docker logs are unavailable.
        var suffix = Guid.NewGuid().ToString("N");
        var id = Guid.NewGuid();
        var name = "Comune Sintetico Registro " + suffix;
        var ticket = "CHANGE-2026-REGISTER-" + suffix;
        var reviewer = "synthetic-reviewer-" + suffix;
        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");

        var result = await RegisterAsync(id.ToString("D"), name, ticket, reviewer,
            logStatements: true);
        Assert.Equal(0, result.Code);
        Assert.False(result.Output.Contains(name, StringComparison.Ordinal)
                     || result.Output.Contains(ticket, StringComparison.Ordinal)
                     || result.Output.Contains(reviewer, StringComparison.Ordinal),
            "psql exposed private synthetic registration markers.");
        var state = await StateAsync(id);
        Assert.Equal((1L, 1L, 0L, 0L, 1L),
            (state.Organizations, state.Modules, state.EnabledModules, state.Memberships, state.Audit));
        Assert.Equal(name, state.Name);

        using var dockerPs = new Process();
        dockerPs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "ps", "--filter", "ancestor=postgres:17-alpine",
                                   "--format", "{{.ID}}" })
            dockerPs.StartInfo.ArgumentList.Add(arg);
        try
        {
            dockerPs.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "Real PostgreSQL 17 service logs must be available in CI.");
            return;
        }
        var containerIds = (await dockerPs.StandardOutput.ReadToEndAsync()).Trim();
        _ = await dockerPs.StandardError.ReadToEndAsync();
        await dockerPs.WaitForExitAsync();
        if (dockerPs.ExitCode != 0 || string.IsNullOrWhiteSpace(containerIds))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "Real PostgreSQL 17 service logs must be inspectable in CI.");
            return;
        }
        Assert.DoesNotContain('\n', containerIds);

        using var logs = new Process();
        logs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "logs", "--since", since, containerIds })
            logs.StartInfo.ArgumentList.Add(arg);
        logs.Start();
        var stdout = logs.StandardOutput.ReadToEndAsync();
        var stderr = logs.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await logs.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, logs.ExitCode);
        var serverLog = await stdout + await stderr;
        Assert.Contains("statement: COPY", serverLog);
        Assert.False(serverLog.Contains(name, StringComparison.Ordinal)
                     || serverLog.Contains(ticket, StringComparison.Ordinal)
                     || serverLog.Contains(reviewer, StringComparison.Ordinal),
            "PostgreSQL statement logs exposed a synthetic registration marker; raw logs withheld.");
    }

    [Fact]
    public async Task Registration_retry_rejects_manually_staged_row_with_wrong_audit_actor()
    {
        var id = Guid.NewGuid();
        const string ticket = "CHANGE-2026-REGISTER132";
        await using (var db = new NpgsqlConnection(OwnerConnection))
        {
            await db.OpenAsync();
            await using var stage = new NpgsqlCommand("""
                INSERT INTO platform.organizations (id, name, is_suspended, is_activated)
                VALUES (@id, 'Comune Sintetico di Prova', FALSE, FALSE);
                INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
                VALUES (@id, 'protocol', FALSE);
                INSERT INTO platform.audit_events
                    (id, organization_id, actor_subject, action, resource_type,
                     resource_id, correlation_id, occurred_at)
                VALUES
                    (gen_random_uuid(), @id, 'synthetic-untrusted-registrar',
                     'platform.organization.registered', 'platform.organization',
                     @id, @correlation, now());
                """, db);
            stage.Parameters.AddWithValue("id", id);
            stage.Parameters.AddWithValue("correlation", "register:" + ticket);
            await stage.ExecuteNonQueryAsync();
        }

        var before = await StateAsync(id);
        var retry = await RegisterAsync(id.ToString("D"), ticket: ticket);
        Assert.NotEqual(0, retry.Code); // RED: matching ticket alone must not adopt a forged actor.
        Assert.DoesNotContain(ticket, retry.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("Comune Sintetico di Prova", retry.Output, StringComparison.Ordinal);
        Assert.Equal(before, await StateAsync(id));
    }

    [Fact]
    public async Task Registration_retry_rejects_extra_registered_audit_with_different_ticket()
    {
        var id = Guid.NewGuid();
        const string originalTicket = "CHANGE-2026-REGISTER132-A";
        const string extraTicket = "CHANGE-2026-REGISTER132-B";
        Assert.Equal(0, (await RegisterAsync(id.ToString("D"), ticket: originalTicket)).Code);
        await using (var db = new NpgsqlConnection(OwnerConnection))
        {
            await db.OpenAsync();
            await using var stage = new NpgsqlCommand("""
                INSERT INTO platform.audit_events
                    (id, organization_id, actor_subject, action, resource_type,
                     resource_id, correlation_id, occurred_at)
                VALUES
                    (gen_random_uuid(), @id, 'synthetic-untrusted-registrar',
                     'platform.organization.registered', 'platform.organization',
                     @id, @correlation, now());
                """, db);
            stage.Parameters.AddWithValue("id", id);
            stage.Parameters.AddWithValue("correlation", "register:" + extraTicket);
            await stage.ExecuteNonQueryAsync();
        }

        var before = await StateAsync(id);
        Assert.Equal(2L, before.Audit);
        var retry = await RegisterAsync(id.ToString("D"), ticket: originalTicket);
        Assert.NotEqual(0, retry.Code); // RED: filtered count of 1 misses the extra event.
        Assert.DoesNotContain(originalTicket, retry.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(extraTicket, retry.Output, StringComparison.Ordinal);
        Assert.Equal(before, await StateAsync(id));
    }
}

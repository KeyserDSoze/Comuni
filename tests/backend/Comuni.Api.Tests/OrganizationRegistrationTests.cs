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
        string? connectionOverride = null)
    {
        var path = Script("register-organization.sql");
        Assert.True(File.Exists(path), "Owner-only organization registration script missing (RED).");
        var database = new NpgsqlConnectionStringBuilder(connectionOverride ?? OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
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
    public async Task Owner_registers_exactly_one_active_empty_tenant_with_protocol_disabled_and_audit()
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
            "UPDATE platform.organizations SET is_suspended=TRUE WHERE id=@id", db);
        change.Parameters.AddWithValue("id", id);
        await change.ExecuteNonQueryAsync();

        Assert.Equal(0, (await RegisterAsync(id.ToString())).Code);
        var state = await StateAsync(id);
        Assert.True(state.Suspended);
        Assert.Equal(0L, state.EnabledModules);
        Assert.Equal(1L, state.Audit);
    }
}

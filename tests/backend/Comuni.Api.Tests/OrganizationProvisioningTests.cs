using System.Diagnostics;
using System.Net;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Real PostgreSQL/psql contract for owner-controlled new-organization provisioning.
/// Never uses real municipalities, external identity providers or Azure.
/// </summary>
public sealed class OrganizationProvisioningTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static string OwnerConnection =>
        Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner connection required.");

    private static string RuntimeConnection =>
        Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted PostgreSQL runtime connection required.");

    private static string ProvisioningScript
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                    return Path.Combine(dir.FullName, "scripts/postgres/provision-organization.sql");
            throw new InvalidOperationException("Repository root was not found.");
        }
    }

    private static async Task<(int ExitCode, string Output)> ProvisionAsync(
        Guid organizationId, string? name = "Comune di Prova",
        string? ticket = "CHANGE-2026-00032",
        string? approver = "reviewer-independent",
        string? connectionOverride = null)
    {
        var script = ProvisioningScript;
        Assert.True(File.Exists(script), "Owner-only organization provisioning script is missing.");
        var db = new NpgsqlConnectionStringBuilder(connectionOverride ?? OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host,
            "-p", db.Port.ToString(), "-U", db.Username, "-d", db.Database,
            "-f", script
        })
            start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = db.Password;
        start.Environment["COMUNI_PROVISION_ORGANIZATION_ID"] = organizationId.ToString("D");
        if (name is null) start.Environment.Remove("COMUNI_PROVISION_ORGANIZATION_NAME");
        else start.Environment["COMUNI_PROVISION_ORGANIZATION_NAME"] = name;
        if (ticket is null) start.Environment.Remove("COMUNI_PROVISION_CHANGE_TICKET");
        else start.Environment["COMUNI_PROVISION_CHANGE_TICKET"] = ticket;
        if (approver is null) start.Environment.Remove("COMUNI_PROVISION_APPROVER");
        else start.Environment["COMUNI_PROVISION_APPROVER"] = approver;

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("psql process could not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(long Organizations, long Modules, long Memberships, long Events)> CountsAsync(Guid id)
    {
        await using var connection = new NpgsqlConnection(OwnerConnection);
        await connection.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT
                (SELECT COUNT(*) FROM platform.organizations WHERE id = @id),
                (SELECT COUNT(*) FROM platform.organization_modules WHERE organization_id = @id),
                (SELECT COUNT(*) FROM platform.organization_memberships WHERE organization_id = @id),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id = @id AND action = 'platform.organization.created')
            """, connection);
        query.Parameters.AddWithValue("id", id);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3));
    }

    [Fact]
    public async Task Owner_provisions_tenant_with_protocol_disabled_no_memberships_and_atomic_audit()
    {
        var id = Guid.NewGuid();
        var name = "Comune d'Ulivo";
        var created = await ProvisionAsync(id, name);
        Assert.Equal(0, created.ExitCode);
        Assert.DoesNotContain(name, created.Output);
        Assert.DoesNotContain("CHANGE-2026-00032", created.Output);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));

        await using var connection = new NpgsqlConnection(OwnerConnection);
        await connection.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT o.name, o.is_suspended, m.enabled, a.actor_subject,
                   a.resource_type, a.resource_id, a.correlation_id
            FROM platform.organizations AS o
            JOIN platform.organization_modules AS m
              ON m.organization_id = o.id AND m.module_key = 'protocol'
            JOIN platform.audit_events AS a
              ON a.organization_id = o.id AND a.action = 'platform.organization.created'
            WHERE o.id = @id
            """, connection);
        query.Parameters.AddWithValue("id", id);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.Equal(name, row.GetString(0));
        Assert.False(row.GetBoolean(1));
        Assert.False(row.GetBoolean(2));
        Assert.StartsWith("db-owner:", row.GetString(3));
        Assert.Equal("platform.organization", row.GetString(4));
        Assert.Equal(id, row.GetGuid(5));
        Assert.Equal("bootstrap:CHANGE-2026-00032", row.GetString(6));

        using var bearer = factory.ClientFor(id.ToString(), "Admin", "forged-admin");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await bearer.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Exact_retry_is_a_noop_and_never_resets_configured_modules()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        await using (var connection = new NpgsqlConnection(OwnerConnection))
        {
            await connection.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE platform.organization_modules SET enabled = TRUE
                WHERE organization_id = @id AND module_key = 'protocol'
                """, connection);
            update.Parameters.AddWithValue("id", id);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
        await using var verify = new NpgsqlConnection(OwnerConnection);
        await verify.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT enabled FROM platform.organization_modules
            WHERE organization_id = @id AND module_key = 'protocol'
            """, verify);
        command.Parameters.AddWithValue("id", id);
        Assert.True((bool)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Existing_mismatched_or_untracked_organization_is_rejected()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: "Un altro Comune")).ExitCode);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));

        var legacyId = Guid.NewGuid();
        await using (var connection = new NpgsqlConnection(OwnerConnection))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("""
                INSERT INTO platform.organizations(id, name)
                VALUES (@id, 'Comune di Prova')
                """, connection);
            command.Parameters.AddWithValue("id", legacyId);
            await command.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await ProvisionAsync(legacyId)).ExitCode);
        Assert.Equal((1L, 0L, 0L, 0L), await CountsAsync(legacyId));
    }

    [Fact]
    public async Task Invalid_inputs_do_not_mutate_any_table()
    {
        var id = Guid.NewGuid();
        Assert.NotEqual(0, (await ProvisionAsync(Guid.Empty)).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: null)).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: " ")).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: " Nome ")).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: "Comune\nInvalido")).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, name: new string('a', 201))).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, ticket: null)).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, approver: null)).ExitCode);
        Assert.NotEqual(0, (await ProvisionAsync(id, ticket: "unsafe ticket")).ExitCode);
        Assert.Equal((0L, 0L, 0L, 0L), await CountsAsync(id));

        var injectionId = Guid.NewGuid();
        var suppliedName = "Comune d'Ulivo'); DROP TABLE platform.organizations;--";
        var safe = await ProvisionAsync(injectionId, name: suppliedName);
        Assert.Equal(0, safe.ExitCode);
        Assert.DoesNotContain(suppliedName, safe.Output);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(injectionId));
    }

    [Fact]
    public async Task Restricted_runtime_account_cannot_provision_a_tenant()
    {
        var id = Guid.NewGuid();
        var denied = await ProvisionAsync(id, connectionOverride: RuntimeConnection);
        Assert.NotEqual(0, denied.ExitCode);
        Assert.Equal((0L, 0L, 0L, 0L), await CountsAsync(id));
    }

    [Fact]
    public async Task Concurrent_requests_for_one_uuid_serialize_and_only_one_identity_wins()
    {
        var id = Guid.NewGuid();
        var tries = await Task.WhenAll(
            ProvisionAsync(id, name: "Comune Prima Prova"),
            ProvisionAsync(id, name: "Comune Seconda Prova")
        );
        Assert.Single(tries.Where(x => x.ExitCode == 0));
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
        Assert.Equal(0, (await ProvisionAsync(id,
            name: tries[0].ExitCode == 0 ? "Comune Prima Prova" : "Comune Seconda Prova")).ExitCode);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
    }
}

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
        string? connectionOverride = null, bool logStatements = false)
    {
        var script = ProvisioningScript;
        Assert.True(File.Exists(script), "Owner-only organization provisioning script is missing.");
        var db = new NpgsqlConnectionStringBuilder(connectionOverride ?? OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            // Required for the static private COPY program; use a trusted checkout root.
            WorkingDirectory = Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(script)!, "..", "..")),
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
        if (logStatements)
            start.Environment["PGOPTIONS"] =
                "-c log_statement=all -c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";
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


    private static async Task<(int ExitCode, string Output)> OwnerLifecycleAsync(
        string scriptName, Guid organizationId)
    {
        // Separate, approved owner-only steps: provisioning never bootstraps
        // identities or activates an organization as a side effect.
        var script = Path.Combine(Path.GetDirectoryName(ProvisioningScript)!, scriptName);
        var db = new NpgsqlConnectionStringBuilder(OwnerConnection);
        var start = new ProcessStartInfo("psql")
        {
            WorkingDirectory = Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(script)!, "..", "..")),
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
        start.Environment["COMUNI_BOOTSTRAP_ORGANIZATION_ID"] = organizationId.ToString("D");
        start.Environment["COMUNI_BOOTSTRAP_IDENTITY_ISSUER"] =
            "https://identity.example.test/tenant/v2.0";
        start.Environment["COMUNI_BOOTSTRAP_SUBJECT"] = "synthetic-provisioning-first-admin";
        start.Environment["COMUNI_BOOTSTRAP_CHANGE_TICKET"] = "CHANGE-2026-ADMIN102";
        start.Environment["COMUNI_BOOTSTRAP_APPROVER"] = "synthetic-reviewer";
        start.Environment["COMUNI_ACTIVATE_ORGANIZATION_ID"] = organizationId.ToString("D");
        start.Environment["COMUNI_ACTIVATE_CHANGE_TICKET"] = "CHANGE-2026-ACTIVATE102";
        start.Environment["COMUNI_ACTIVATE_APPROVER"] = "synthetic-reviewer";

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Owner lifecycle psql process unavailable.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(bool Activated, bool Suspended, long ActiveAdmins,
        long Activations)> LifecycleAsync(Guid id)
    {
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT o.is_activated, o.is_suspended,
                   (SELECT count(*) FROM platform.organization_memberships
                    WHERE organization_id=@id AND role='Admin' AND is_active),
                   (SELECT count(*) FROM platform.audit_events
                    WHERE organization_id=@id AND action='platform.organization.activated')
            FROM platform.organizations o
            WHERE o.id=@id
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var rd = await cmd.ExecuteReaderAsync();
        Assert.True(await rd.ReadAsync());
        return (rd.GetBoolean(0), rd.GetBoolean(1), rd.GetInt64(2), rd.GetInt64(3));
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
    public async Task A_different_approved_ticket_cannot_be_claimed_as_a_legacy_provisioning_retry()
    {
        var id = Guid.NewGuid();
        const string originalTicket = "CHANGE-2026-LEGACY-130A";
        const string unrelatedTicket = "CHANGE-2026-LEGACY-130B";
        const string name = "Synthetic municipality change provenance";
        Assert.Equal(0, (await ProvisionAsync(id, name, originalTicket)).ExitCode);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));

        // Same ID and municipality name, but NOT the same approved change.
        // A no-op success would misleadingly attest the unrelated ticket.
        var rejected = await ProvisionAsync(id, name, unrelatedTicket);
        Assert.NotEqual(0, rejected.ExitCode);
        Assert.DoesNotContain(originalTicket, rejected.Output);
        Assert.DoesNotContain(unrelatedTicket, rejected.Output);
        Assert.DoesNotContain(name, rejected.Output);

        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var audit = new NpgsqlCommand("""
            SELECT correlation_id FROM platform.audit_events
            WHERE organization_id=@org AND action='platform.organization.created'
            """, db);
        audit.Parameters.AddWithValue("org", id);
        Assert.Equal("bootstrap:" + originalTicket, await audit.ExecuteScalarAsync());

        // A genuine retry of the *original* externally approved ticket
        // remains idempotent and does not add an event.
        Assert.Equal(0, (await ProvisionAsync(id, name, originalTicket)).ExitCode);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
    }

    [Fact]
    public async Task A_manual_created_event_with_a_non_owner_actor_is_not_legacy_provenance()
    {
        var id = Guid.NewGuid();
        const string name = "Synthetic municipality with forged provenance";
        const string ticket = "CHANGE-2026-LEGACY-130C";
        await using (var db = new NpgsqlConnection(OwnerConnection))
        {
            await db.OpenAsync();
            await using var seed = new NpgsqlCommand("""
                INSERT INTO platform.organizations(id,name,is_suspended,is_activated)
                VALUES (@org,@name,FALSE,FALSE);
                INSERT INTO platform.organization_modules(organization_id,module_key,enabled)
                VALUES (@org,'protocol',FALSE);
                INSERT INTO platform.audit_events
                    (id,organization_id,actor_subject,action,resource_type,
                     resource_id,correlation_id,occurred_at)
                VALUES (gen_random_uuid(),@org,'synthetic-untrusted-actor',
                    'platform.organization.created','platform.organization',
                    @org,@correlation,now())
                """, db);
            seed.Parameters.AddWithValue("org", id);
            seed.Parameters.AddWithValue("name", name);
            seed.Parameters.AddWithValue("correlation", "bootstrap:" + ticket);
            await seed.ExecuteNonQueryAsync();
        }

        // A matching action/ticket/resource alone is insufficient proof of
        // the owner-only script having created this row.
        var rejected = await ProvisionAsync(id, name, ticket);
        Assert.NotEqual(0, rejected.ExitCode);
        Assert.DoesNotContain(name, rejected.Output);
        Assert.DoesNotContain(ticket, rejected.Output);
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));
        Assert.Equal((false, false, 0L, 0L), await LifecycleAsync(id));
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

    [Fact]
    public async Task Provisioning_SQL_must_not_inline_private_change_or_municipality_inputs()
    {
        var sql = await File.ReadAllTextAsync(ProvisioningScript);
        foreach (var name in new[] {
            "provision_org", "provision_name", "provision_ticket", "provision_approver"
        })
            Assert.DoesNotContain(":'" + name + "'", sql);
        Assert.Contains("FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py provision-organization'", sql);
    }

    [Fact]
    public async Task Owner_provisioning_private_name_ticket_reviewer_do_not_appear_in_real_Postgres_statement_logs()
    {
        // Only synthetic unique markers; never report canaries or raw log contents.
        // A missing PostgreSQL 17 service log is a CI test failure, never a skip.
        var marker = Guid.NewGuid().ToString("N");
        var id = Guid.NewGuid();
        var name = "Comune Sintetico Provision " + marker;
        var ticket = "CHANGE-2026-PROVISION-" + marker;
        var reviewer = "synthetic-reviewer-" + marker;
        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");

        var created = await ProvisionAsync(id, name, ticket, reviewer, logStatements: true);
        Assert.Equal(0, created.ExitCode);
        Assert.False(created.Output.Contains(name, StringComparison.Ordinal)
                     || created.Output.Contains(ticket, StringComparison.Ordinal)
                     || created.Output.Contains(reviewer, StringComparison.Ordinal),
            "psql output exposed a synthetic private provisioning marker.");
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));

        using var dockerPs = new Process();
        dockerPs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
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
            RedirectStandardOutput = true,
            RedirectStandardError = true,
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
            "PostgreSQL statement log exposed a synthetic provisioning marker; raw logs withheld.");
    }

    [Fact]
    public async Task Legacy_owner_provisioning_creates_pending_and_requires_separate_Admin_and_activation()
    {
        var id = Guid.NewGuid();
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        Assert.Equal((false, false, 0L, 0L), await LifecycleAsync(id));
        Assert.Equal((1L, 1L, 0L, 1L), await CountsAsync(id));

        // Without the first verified OIDC Admin, even the owner activation
        // must reject and preserve the created state.
        Assert.NotEqual(0, (await OwnerLifecycleAsync("activate-organization.sql", id)).ExitCode);
        Assert.Equal((false, false, 0L, 0L), await LifecycleAsync(id));

        Assert.Equal(0, (await OwnerLifecycleAsync("bootstrap-initial-admin.sql", id)).ExitCode);
        Assert.Equal((false, false, 1L, 0L), await LifecycleAsync(id));

        // Explicit test-only Reader membership exercises the real API gate
        // with a valid DevelopmentJwt while OIDC Admin uses an issuer-bound ID.
        await using (var db = new NpgsqlConnection(OwnerConnection))
        {
            await db.OpenAsync();
            await using var add = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id,subject,role,is_active)
                VALUES (@org,'legacy-provision-reader','Reader',TRUE)
                """, db);
            add.Parameters.AddWithValue("org", id);
            await add.ExecuteNonQueryAsync();
        }
        using var reader = factory.ClientFor(id.ToString(), "Reader", "legacy-provision-reader");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);

        // An idempotent retry may not bypass approval or change memberships.
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        Assert.Equal((false, false, 1L, 0L), await LifecycleAsync(id));

        Assert.Equal(0, (await OwnerLifecycleAsync("activate-organization.sql", id)).ExitCode);
        Assert.Equal((true, false, 1L, 1L), await LifecycleAsync(id));
        Assert.Equal(HttpStatusCode.OK,
            (await reader.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await reader.GetAsync("/api/v1/protocol/records")).StatusCode);

        // No duplicate activation audit or implicit state changes on retry.
        Assert.Equal(0, (await ProvisionAsync(id)).ExitCode);
        Assert.Equal(0, (await OwnerLifecycleAsync("activate-organization.sql", id)).ExitCode);
        Assert.Equal((true, false, 1L, 1L), await LifecycleAsync(id));
        Assert.Equal((1L, 1L, 2L, 1L), await CountsAsync(id));
    }

    [Fact]
    public async Task Existing_legacy_active_and_suspended_organizations_keep_their_default_state()
    {
        // Compatibility default TRUE is intentionally retained for existing
        // legacy inserts; only newly provisioned tenants must override FALSE.
        var active = Guid.NewGuid();
        var suspended = Guid.NewGuid();
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id,name,is_suspended)
            VALUES (@active, 'Existing Active Synthetic', FALSE),
                   (@suspended, 'Existing Suspended Synthetic', TRUE)
            """, db);
        insert.Parameters.AddWithValue("active", active);
        insert.Parameters.AddWithValue("suspended", suspended);
        await insert.ExecuteNonQueryAsync();
        Assert.Equal((true, false, 0L, 0L), await LifecycleAsync(active));
        Assert.Equal((true, true, 0L, 0L), await LifecycleAsync(suspended));
        Assert.NotEqual(0, (await ProvisionAsync(active, "Existing Active Synthetic")).ExitCode);
        Assert.Equal((true, false, 0L, 0L), await LifecycleAsync(active));
    }
}

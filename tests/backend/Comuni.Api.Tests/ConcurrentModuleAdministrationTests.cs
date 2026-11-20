using System.Diagnostics;
using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first #129: overlapping Admin toggle transactions must be a single
/// logical state transition and a single audit event, even under signed RLS.
/// The database and both writer logins are real and disposable in CI.
/// </summary>
public sealed class ConcurrentModuleAdministrationTests
{
    private static string Owner => Environment.GetEnvironmentVariable(
        "TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner login required.");

    private static string Runtime => Environment.GetEnvironmentVariable(
        "TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted PostgreSQL login required.");

    private sealed class Organization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }

    private static TenantProofSigner Signer() => new(
        Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Synthetic RLS signing key required."));

    private static async Task<Guid> Seed()
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id, name)
            VALUES (@org, 'Synthetic concurrent-module municipality');
            INSERT INTO platform.organization_modules(organization_id, module_key, enabled)
            VALUES (@org, 'protocol', TRUE);
            """, db);
        command.Parameters.AddWithValue("org", id);
        await command.ExecuteNonQueryAsync();
        return id;
    }

    private static async Task<(bool Enabled, long Disabled, long EnabledEvents)> Read(Guid org)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT
                (SELECT enabled FROM platform.organization_modules
                 WHERE organization_id=@org AND module_key='protocol'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@org AND action='platform.module.protocol.disabled'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@org AND action='platform.module.protocol.enabled')
            """, db);
        command.Parameters.AddWithValue("org", org);
        await using var row = await command.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetBoolean(0), row.GetInt64(1), row.GetInt64(2));
    }

    private static async Task<ModuleUpdateStatus> Toggle(Guid org, bool target, string app)
    {
        var connection = new NpgsqlConnectionStringBuilder(Runtime)
        {
            ApplicationName = app,
            CommandTimeout = 30,
            Timeout = 10
        }.ConnectionString;
        await using var db = new ComuniDbContext(
            new DbContextOptionsBuilder<ComuniDbContext>()
                .UseNpgsql(connection).Options,
            new Organization(org));
        var signer = Signer();
        await using var tx = await TenantDatabaseTransaction.BeginAsync(
            db, signer, CancellationToken.None);
        var repo = new ModuleAdministrationRepository(db, signer);
        var audit = AuditEvent.Create(
            org, "synthetic-verified-admin",
            target ? "platform.module.protocol.enabled" : "platform.module.protocol.disabled",
            "platform.module", org, "synthetic-parallel-admin-toggle");
        var status = await repo.SetEnabledAsync(
            org, "protocol", target, audit, CancellationToken.None);
        await tx.CommitAsync();
        return status;
    }

    private static async Task<ModuleUpdateStatus[]> TwoOverlappingToggles(
        Guid org, bool desired)
    {
        // Hold a row-level lock before either writer starts. The old code
        // reads the enabled flag WITHOUT FOR UPDATE; both writers then block
        // on their UPDATE and each invents an audit. The fixed code blocks
        // on SELECT FOR UPDATE, then re-reads under READ COMMITTED.
        var app = "comuni-toggle-" + Guid.NewGuid().ToString("N");
        await using var controller = new NpgsqlConnection(Owner);
        await controller.OpenAsync();
        await using var gate = await controller.BeginTransactionAsync();
        await using (var lockRow = new NpgsqlCommand("""
            SELECT enabled FROM platform.organization_modules
            WHERE organization_id=@org AND module_key='protocol' FOR UPDATE
            """, controller, gate))
        {
            lockRow.Parameters.AddWithValue("org", org);
            Assert.IsType<bool>(await lockRow.ExecuteScalarAsync());
        }

        var first = Task.Run(() => Toggle(org, desired, app));
        var second = Task.Run(() => Toggle(org, desired, app));
        try
        {
            // Do not release the gate based on timing alone: wait until
            // both *independent* SQL sessions have reached a lock wait.
            // Synthetic application_name isolates this test from unrelated
            // parallel PostgreSQL integration tests.
            var watch = Stopwatch.StartNew();
            long blocked = 0;
            while (watch.Elapsed < TimeSpan.FromSeconds(20))
            {
                await using var waiting = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_stat_activity
                    WHERE application_name=@app AND wait_event_type='Lock'
                      AND state='active'
                    """, controller, gate);
                waiting.Parameters.AddWithValue("app", app);
                blocked = (long)(await waiting.ExecuteScalarAsync())!;
                if (blocked == 2) break;
                await Task.Delay(80);
            }
            Assert.Equal(2L, blocked);
        }
        finally
        {
            // Always unblock both writers, including when the test fails.
            await gate.CommitAsync();
        }

        var statuses = await Task.WhenAll(first, second);
        return statuses.OrderBy(x => x).ToArray();
    }

    [Fact]
    public async Task Duplicate_concurrent_disables_and_enables_are_single_transitions_and_audits()
    {
        var own = await Seed();
        var other = await Seed();

        Assert.Equal(new[] { ModuleUpdateStatus.Unchanged, ModuleUpdateStatus.Updated },
            await TwoOverlappingToggles(own, desired: false));
        Assert.Equal((false, 1L, 0L), await Read(own));
        Assert.Equal((true, 0L, 0L), await Read(other));

        Assert.Equal(new[] { ModuleUpdateStatus.Unchanged, ModuleUpdateStatus.Updated },
            await TwoOverlappingToggles(own, desired: true));
        Assert.Equal((true, 1L, 1L), await Read(own));
        Assert.Equal((true, 0L, 0L), await Read(other));
    }
}

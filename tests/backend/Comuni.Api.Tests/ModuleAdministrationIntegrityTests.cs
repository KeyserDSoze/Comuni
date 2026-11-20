using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// A repository cannot store a truthful module state beside a forged audit action.
/// These tests use the actual restricted SQL login and signed PostgreSQL RLS proof.
/// </summary>
public sealed class ModuleAdministrationIntegrityTests
{
    private static string OwnerConnection => Environment.GetEnvironmentVariable(
        "TEST_DATABASE_CONNECTION") ?? throw new InvalidOperationException(
        "PostgreSQL 17 owner test connection is required.");

    private static string RuntimeConnection => Environment.GetEnvironmentVariable(
        "TEST_RUNTIME_DATABASE_CONNECTION") ?? throw new InvalidOperationException(
        "PostgreSQL 17 restricted runtime connection is required.");

    private static TenantProofSigner Signer() => new(
        Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Synthetic signed RLS key required."));

    private sealed class TestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }

    private static async Task<Guid> SeedAsync()
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id,name)
            VALUES (@org, 'Synthetic Module Audit Guard');
            INSERT INTO platform.organization_modules (organization_id,module_key,enabled)
            VALUES (@org, 'protocol', TRUE);
            """, db);
        command.Parameters.AddWithValue("org", id);
        await command.ExecuteNonQueryAsync();
        return id;
    }

    private static async Task<(bool Enabled, long AuditCount)> ReadAsync(Guid id)
    {
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT m.enabled,
              (SELECT count(*) FROM platform.audit_events
               WHERE organization_id = @org AND resource_type = 'platform.module')
            FROM platform.organization_modules AS m
            WHERE m.organization_id = @org AND m.module_key = 'protocol'
            """, db);
        command.Parameters.AddWithValue("org", id);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetBoolean(0), reader.GetInt64(1));
    }

    private static AuditEvent Event(Guid organizationId, bool enabled,
        string? action = null, string resourceType = "platform.module",
        Guid? resourceId = null, Guid? auditOrganization = null) =>
        AuditEvent.Create(
            auditOrganization ?? organizationId, "synthetic-verified-admin",
            action ?? (enabled ? "platform.module.protocol.enabled" : "platform.module.protocol.disabled"),
            resourceType, resourceId ?? organizationId, "synthetic-server-correlation");

    private static ComuniDbContext RuntimeDb(Guid id) =>
        new(new DbContextOptionsBuilder<ComuniDbContext>()
            .UseNpgsql(RuntimeConnection).Options, new TestOrganization(id));

    [Fact]
    public async Task Forged_module_audit_and_cross_tenant_operations_fail_before_any_write()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        await using var db = RuntimeDb(own);
        var signer = Signer();
        await using var transaction = await TenantDatabaseTransaction.BeginAsync(
            db, signer, CancellationToken.None);
        var repository = new ModuleAdministrationRepository(db, signer);

        var invalid = new[]
        {
            ("wrong action", own, "protocol", Event(own, false, "platform.module.protocol.enabled")),
            ("unrelated action", own, "protocol", Event(own, false, "platform.membership.reader.activated")),
            ("wrong resource type", own, "protocol", Event(own, false, resourceType: "platform.membership")),
            ("wrong resource", own, "protocol", Event(own, false, resourceId: other)),
            ("wrong audit organization", own, "protocol", Event(own, false, auditOrganization: other)),
            ("unrecognized module", own, "unknown", Event(own, false)),
            ("cross tenant write", other, "protocol", Event(other, false)),
            ("empty tenant", Guid.Empty, "protocol", Event(own, false))
        };

        foreach (var test in invalid)
        {
            var failure = await Record.ExceptionAsync(() =>
                repository.SetEnabledAsync(test.Item2, test.Item3, false, test.Item4, CancellationToken.None));
            Assert.IsType<UnauthorizedAccessException>(failure);
        }

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(other, CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(Guid.Empty, CancellationToken.None));

        Assert.Equal((true, 0L), await ReadAsync(own));
        Assert.Equal((true, 0L), await ReadAsync(other));
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task Consistent_audit_is_atomically_committed_and_idempotent_without_duplicates()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        var signer = Signer();
        await using (var db = RuntimeDb(own))
        {
            await using var transaction = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            var repo = new ModuleAdministrationRepository(db, signer);
            Assert.Single(await repo.ListAsync(own, CancellationToken.None));
            Assert.Equal(ModuleUpdateStatus.Updated,
                await repo.SetEnabledAsync(own, "protocol", false, Event(own, false), CancellationToken.None));
            Assert.Equal(ModuleUpdateStatus.Unchanged,
                await repo.SetEnabledAsync(own, "protocol", false, Event(own, false), CancellationToken.None));
            await transaction.CommitAsync();
        }
        Assert.Equal((false, 1L), await ReadAsync(own));
        Assert.Equal((true, 0L), await ReadAsync(other));

        await using (var db = RuntimeDb(own))
        {
            await using var transaction = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            var repo = new ModuleAdministrationRepository(db, signer);
            Assert.Equal(ModuleUpdateStatus.Updated,
                await repo.SetEnabledAsync(own, "protocol", true, Event(own, true), CancellationToken.None));
            await transaction.RollbackAsync();
        }
        Assert.Equal((false, 1L), await ReadAsync(own));

        await using (var db = RuntimeDb(own))
        {
            await using var transaction = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            var repo = new ModuleAdministrationRepository(db, signer);
            Assert.Equal(ModuleUpdateStatus.Updated,
                await repo.SetEnabledAsync(own, "protocol", true, Event(own, true), CancellationToken.None));
            await transaction.CommitAsync();
        }
        Assert.Equal((true, 2L), await ReadAsync(own));
        Assert.Equal((true, 0L), await ReadAsync(other));
    }

    [Fact]
    public async Task Tracked_module_state_must_be_refreshed_after_another_transaction_commits()
    {
        // Reproduces a different interleaving from the simultaneous-write
        // regression: this DbContext tracked the flag before another writer
        // acquired the row lock and committed its change.
        var own = await SeedAsync();
        var other = await SeedAsync();
        await VerifyStaleTrackedToggleAsync(own, other, desired: false, expectedAudits: 1);
        await VerifyStaleTrackedToggleAsync(own, other, desired: true, expectedAudits: 2);
    }

    private static async Task VerifyStaleTrackedToggleAsync(
        Guid own, Guid other, bool desired, long expectedAudits)
    {
        var signer = Signer();
        await using var staleDb = RuntimeDb(own);
        await using var staleTx = await TenantDatabaseTransaction.BeginAsync(
            staleDb, signer, CancellationToken.None);

        // Keep the first EF entity instance tracked while another SQL session
        // performs the real transition, with signed tenant RLS in both sessions.
        var tracked = await staleDb.OrganizationModules.SingleAsync(
            m => m.OrganizationId == own && m.ModuleKey == "protocol");
        Assert.Equal(!desired, tracked.Enabled);

        await using (var freshDb = RuntimeDb(own))
        {
            await using var freshTx = await TenantDatabaseTransaction.BeginAsync(
                freshDb, signer, CancellationToken.None);
            var writer = new ModuleAdministrationRepository(freshDb, signer);
            Assert.Equal(ModuleUpdateStatus.Updated,
                await writer.SetEnabledAsync(
                    own, "protocol", desired, Event(own, desired), CancellationToken.None));
            await freshTx.CommitAsync();
        }

        // The stale context must re-read the database state after FOR UPDATE:
        // an EF tracking query by itself returns the previously tracked value.
        Assert.Equal(!desired, tracked.Enabled);
        var staleWriter = new ModuleAdministrationRepository(staleDb, signer);
        Assert.Equal(ModuleUpdateStatus.Unchanged,
            await staleWriter.SetEnabledAsync(
                own, "protocol", desired, Event(own, desired), CancellationToken.None));
        await staleTx.CommitAsync();

        Assert.Equal((desired, expectedAudits), await ReadAsync(own));
        Assert.Equal((true, 0L), await ReadAsync(other));
    }
}

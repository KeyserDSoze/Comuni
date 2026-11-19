using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Comuni.Domains.Protocol;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Direct protocol repository integrity on restricted PostgreSQL 17 runtime
/// and transaction-local signed tenant RLS. All data is synthetic.
/// </summary>
public sealed class ProtocolRepositoryIntegrityTests
{
    private static string OwnerConnection =>
        Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Synthetic PostgreSQL owner connection required.");

    private static string RuntimeConnection =>
        Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted PostgreSQL runtime connection required.");

    private static TenantProofSigner Signer() => new(
        Environment.GetEnvironmentVariable("Security__TenantProofKey")
        ?? throw new InvalidOperationException("Synthetic tenant signing key required."));

    private sealed class TestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }

    private static ComuniDbContext RuntimeDb(Guid id) =>
        new(new DbContextOptionsBuilder<ComuniDbContext>()
            .UseNpgsql(RuntimeConnection).Options, new TestOrganization(id));

    private static async Task<Guid> SeedAsync()
    {
        var organizationId = Guid.NewGuid();
        await using var conn = new NpgsqlConnection(OwnerConnection);
        await conn.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id,name)
                VALUES (@organization, 'Synthetic Protocol Audit Integrity');
            INSERT INTO platform.organization_modules(organization_id,module_key,enabled)
                VALUES (@organization, 'protocol', TRUE);
            """, conn);
        command.Parameters.AddWithValue("organization", organizationId);
        await command.ExecuteNonQueryAsync();
        return organizationId;
    }

    private static AuditEvent Audit(ProtocolRecord record,
        string action = "protocol.record.created", string type = "protocol.record",
        Guid? resource = null, Guid? organization = null) =>
        AuditEvent.Create(organization ?? record.OrganizationId,
            "synthetic-protocol-officer", action, type,
            resource ?? record.Id, "synthetic-server-correlation");

    private static async Task<(long Records, long AuditEvents)> CountsAsync(Guid org)
    {
        await using var conn = new NpgsqlConnection(OwnerConnection);
        await conn.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT (SELECT count(*) FROM protocol.records WHERE organization_id=@org),
                   (SELECT count(*) FROM platform.audit_events WHERE organization_id=@org)
            """, conn);
        command.Parameters.AddWithValue("org", org);
        await using var row = await command.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetInt64(0), row.GetInt64(1));
    }

    [Fact]
    public async Task Invalid_protocol_audit_and_cross_tenant_access_fail_without_any_sql_write()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        var record = ProtocolRecord.Register(own, "Synthetic protocol metadata");
        var foreignRecord = ProtocolRecord.Register(other, "Foreign synthetic protocol");
        var signer = Signer();
        await using var db = RuntimeDb(own);
        await using var transaction = await TenantDatabaseTransaction.BeginAsync(
            db, signer, CancellationToken.None);
        var repository = new ProtocolRepository(db, signer);

        var invalid = new (string Scenario, ProtocolRecord Record, AuditEvent Audit)[]
        {
            ("wrong action", record, Audit(record, "protocol.record.deleted")),
            ("membership action", record, Audit(record, "platform.membership.reader.activated")),
            ("module action", record, Audit(record, "platform.module.protocol.enabled")),
            ("wrong resource type", record, Audit(record, type:"platform.module")),
            ("wrong resource ID", record, Audit(record, resource:Guid.NewGuid())),
            ("wrong audit tenant", record, Audit(record, organization:other)),
            ("foreign record", foreignRecord, Audit(foreignRecord))
        };

        foreach (var scenario in invalid)
        {
            var failure = await Record.ExceptionAsync(() =>
                repository.AddAsync(scenario.Record, scenario.Audit, CancellationToken.None));
            Assert.IsType<UnauthorizedAccessException>(failure);
        }

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(other, CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(Guid.Empty, CancellationToken.None));
        Assert.Empty(await repository.ListAsync(own, CancellationToken.None));

        Assert.Equal((0L, 0L), await CountsAsync(own));
        Assert.Equal((0L, 0L), await CountsAsync(other));
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task Correct_protocol_audit_commits_atomically_and_rollback_removes_both()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        var signer = Signer();

        var committed = ProtocolRecord.Register(own, "Synthetic committed record");
        await using (var db = RuntimeDb(own))
        {
            await using var tx = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            var repository = new ProtocolRepository(db, signer);
            await repository.AddAsync(committed, Audit(committed), CancellationToken.None);
            Assert.Single(await repository.ListAsync(own, CancellationToken.None));
            await tx.CommitAsync();
        }
        Assert.Equal((1L, 1L), await CountsAsync(own));

        var rolledBack = ProtocolRecord.Register(own, "Synthetic rolled-back record");
        await using (var db = RuntimeDb(own))
        {
            await using var tx = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            await new ProtocolRepository(db, signer).AddAsync(
                rolledBack, Audit(rolledBack), CancellationToken.None);
            await tx.RollbackAsync();
        }
        Assert.Equal((1L, 1L), await CountsAsync(own));
        Assert.Equal((0L, 0L), await CountsAsync(other));

        // A direct repository invocation remains valid with its own signed
        // transaction when no HTTP middleware transaction is present.
        var selfManaged = ProtocolRecord.Register(own, "Synthetic self-managed record");
        await using (var db = RuntimeDb(own))
            await new ProtocolRepository(db, signer).AddAsync(
                selfManaged, Audit(selfManaged), CancellationToken.None);

        Assert.Equal((2L, 2L), await CountsAsync(own));
        Assert.Equal((0L, 0L), await CountsAsync(other));
    }
}

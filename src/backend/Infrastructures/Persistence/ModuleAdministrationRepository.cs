using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Comuni.Infrastructures.Persistence;

public sealed class ModuleAdministrationRepository(ComuniDbContext db, TenantProofSigner signer) : IModuleAdministrationStore
{
    public async Task<IReadOnlyList<ModuleState>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        RequireCurrentOrganization(organizationId);
        return await db.OrganizationModules.AsNoTracking()
            .Where(m => m.OrganizationId == organizationId && m.ModuleKey == ModuleCatalog.ProtocolKey)
            .OrderBy(m => m.ModuleKey)
            .Select(m => new ModuleState(m.ModuleKey, m.Enabled))
            .ToListAsync(cancellationToken);
    }

    private void RequireCurrentOrganization(Guid organizationId)
    {
        // Fail explicitly before a query; EF filters and PostgreSQL signed
        // tenant RLS remain independent guards on the database connection.
        if (organizationId == Guid.Empty || db.CurrentOrganizationId != organizationId)
            throw new UnauthorizedAccessException("Module administration tenant context mismatch.");
    }

    public async Task<ModuleUpdateStatus> SetEnabledAsync(
        Guid organizationId, string moduleKey, bool enabled,
        AuditEvent audit, CancellationToken cancellationToken)
    {
        RequireCurrentOrganization(organizationId);
        // A repository caller cannot persist a module state beside an
        // unrelated or reversed audit action. Enforce the Business contract
        // again before the first SQL statement and before attaching the event.
        var expectedAction = enabled
            ? "platform.module.protocol.enabled"
            : "platform.module.protocol.disabled";
        if (!ModuleCatalog.IsImplemented(moduleKey) ||
            audit.OrganizationId != organizationId ||
            audit.ResourceId != organizationId ||
            audit.ResourceType != "platform.module" ||
            audit.Action != expectedAction)
            throw new UnauthorizedAccessException("Module administration audit contract mismatch.");

        var ownsTransaction = db.Database.CurrentTransaction is null;
        await using var transaction = ownsTransaction
            ? await TenantDatabaseTransaction.BeginAsync(db, signer, cancellationToken)
            : null;
        // Acquire the per-organization row lock BEFORE reading the state.
        // Two concurrent requests for the same target must not both create
        // an audit event for a single transition. The lock uses the existing
        // signed tenant RLS transaction, never an owner or global lock.
        await using (var rowLock = db.Database.GetDbConnection().CreateCommand())
        {
            rowLock.Transaction = db.Database.CurrentTransaction!.GetDbTransaction();
            rowLock.CommandText = """
                SELECT 1 FROM platform.organization_modules
                WHERE organization_id = @organizationId AND module_key = @moduleKey
                FOR UPDATE
                """;

            var org = rowLock.CreateParameter();
            org.ParameterName = "organizationId";
            org.Value = organizationId;
            rowLock.Parameters.Add(org);

            var key = rowLock.CreateParameter();
            key.ParameterName = "moduleKey";
            key.Value = moduleKey;
            rowLock.Parameters.Add(key);

            // Missing flag is not implicitly provisioned by an Admin.
            if (await rowLock.ExecuteScalarAsync(cancellationToken) is null)
                return ModuleUpdateStatus.NotFound;
        }

        // Under PostgreSQL READ COMMITTED, a concurrent writer that was
        // awaited by FOR UPDATE is now visible to this fresh EF read.
        var module = await db.OrganizationModules.SingleOrDefaultAsync(
            m => m.OrganizationId == organizationId && m.ModuleKey == moduleKey, cancellationToken);

        if (module is null) return ModuleUpdateStatus.NotFound;

        // FOR UPDATE serializes SQL writers, but an EF tracking query can
        // return an entity materialized BEFORE another transaction committed.
        // Refresh its properties from PostgreSQL while still holding the lock
        // before deciding whether this request represents a new transition.
        await db.Entry(module).ReloadAsync(cancellationToken);
        if (db.Entry(module).State == EntityState.Detached)
            return ModuleUpdateStatus.NotFound;
        if (module.Enabled == enabled) return ModuleUpdateStatus.Unchanged;

        module.SetEnabled(enabled);
        await db.AuditEvents.AddAsync(audit, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        return ModuleUpdateStatus.Updated;
    }
}

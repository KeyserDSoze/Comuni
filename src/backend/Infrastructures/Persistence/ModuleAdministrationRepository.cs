using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class ModuleAdministrationRepository(ComuniDbContext db, TenantProofSigner signer) : IModuleAdministrationStore
{
    public async Task<IReadOnlyList<ModuleState>> ListAsync(Guid organizationId, CancellationToken cancellationToken) =>
        await db.OrganizationModules.AsNoTracking()
            .Where(m => m.OrganizationId == organizationId && m.ModuleKey == "protocol")
            .OrderBy(m => m.ModuleKey)
            .Select(m => new ModuleState(m.ModuleKey, m.Enabled))
            .ToListAsync(cancellationToken);

    public async Task<ModuleUpdateStatus> SetEnabledAsync(
        Guid organizationId, string moduleKey, bool enabled,
        AuditEvent audit, CancellationToken cancellationToken)
    {
        if (audit.OrganizationId != organizationId || audit.ResourceId != organizationId)
            throw new ArgumentException("Audit entry must belong to the current organization.", nameof(audit));

        var ownsTransaction = db.Database.CurrentTransaction is null;
        await using var transaction = ownsTransaction
            ? await TenantDatabaseTransaction.BeginAsync(db, signer, cancellationToken)
            : null;
        var module = await db.OrganizationModules.SingleOrDefaultAsync(
            m => m.OrganizationId == organizationId && m.ModuleKey == moduleKey, cancellationToken);

        if (module is null) return ModuleUpdateStatus.NotFound;
        if (module.Enabled == enabled) return ModuleUpdateStatus.Unchanged;

        module.SetEnabled(enabled);
        await db.AuditEvents.AddAsync(audit, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if (transaction is not null) await transaction.CommitAsync(cancellationToken);
        return ModuleUpdateStatus.Updated;
    }
}

using Comuni.Business.Protocol;
using Comuni.Domains.Audit;
using Comuni.Domains.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class ProtocolRepository(ComuniDbContext db, TenantProofSigner signer) : IProtocolRepository
{
    public async Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        return await db.ProtocolRecords.AsNoTracking()
            .Where(r => r.OrganizationId == organizationId)
            .OrderByDescending(r => r.RegisteredAt)
            .Take(100)
            .ToListAsync(cancellationToken);
    }

    public async Task AddAsync(ProtocolRecord record, AuditEvent audit, CancellationToken cancellationToken)
    {
        if (audit.OrganizationId != record.OrganizationId || audit.ResourceId != record.Id)
            throw new ArgumentException("Audit entry must match the registered protocol record.", nameof(audit));

        // Explicit transaction: both writes succeed or both are rolled back.
        // API requests already own a tenant-scoped transaction; direct repository use
        // creates an equivalent scope instead of attempting a nested transaction.
        var ownsTransaction = db.Database.CurrentTransaction is null;
        await using var tx = ownsTransaction
            ? await TenantDatabaseTransaction.BeginAsync(db, signer, cancellationToken)
            : null;
        await db.ProtocolRecords.AddAsync(record, cancellationToken);
        await db.AuditEvents.AddAsync(audit, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if (tx is not null) await tx.CommitAsync(cancellationToken);
    }
}

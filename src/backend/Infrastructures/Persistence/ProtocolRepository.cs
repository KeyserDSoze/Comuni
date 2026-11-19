using Comuni.Business.Protocol;
using Comuni.Domains.Audit;
using Comuni.Domains.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class ProtocolRepository(ComuniDbContext db, TenantProofSigner signer) : IProtocolRepository
{
    public async Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        RequireCurrentOrganization(organizationId);
        return await db.ProtocolRecords.AsNoTracking()
            .Where(r => r.OrganizationId == organizationId)
            .OrderByDescending(r => r.RegisteredAt)
            .Take(100)
            .ToListAsync(cancellationToken);
    }

    private void RequireCurrentOrganization(Guid organizationId)
    {
        // A caller cannot override the verified tenant, even if the SQL RLS
        // and EF query filters would independently deny a foreign record.
        if (organizationId == Guid.Empty || db.CurrentOrganizationId != organizationId)
            throw new UnauthorizedAccessException("Protocol repository tenant context mismatch.");
    }

    public async Task AddAsync(ProtocolRecord record, AuditEvent audit, CancellationToken cancellationToken)
    {
        RequireCurrentOrganization(record.OrganizationId);
        // The audit must describe the exact record creation committed here.
        // An atomic transaction cannot make a semantically forged event true.
        if (record.Id == Guid.Empty ||
            audit.OrganizationId != record.OrganizationId ||
            audit.ResourceId != record.Id ||
            audit.Action != "protocol.record.created" ||
            audit.ResourceType != "protocol.record")
            throw new UnauthorizedAccessException("Protocol repository audit contract mismatch.");

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

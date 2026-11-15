using Comuni.Business.Protocol;
using Comuni.Domains.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class ProtocolRepository(ComuniDbContext db) : IProtocolRepository
{
    public async Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        return await db.ProtocolRecords.AsNoTracking()
            .Where(r => r.OrganizationId == organizationId)
            .OrderByDescending(r => r.RegisteredAt)
            .Take(100)
            .ToListAsync(cancellationToken);
    }

    public async Task AddAsync(ProtocolRecord record, CancellationToken cancellationToken)
    {
        await db.ProtocolRecords.AddAsync(record, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }
}

using Comuni.Business.Audit;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Must be run inside the signed, transaction-scoped tenant proof established
/// by the API. Never IgnoreQueryFilters or use the schema-owner connection.
/// PostgreSQL grants SELECT on only the five columns needed for filtering and
/// projection; actor, correlation and resource identifiers are not readable.
/// </summary>
public sealed class OrganizationAuditReader(ComuniDbContext db) : IOrganizationAuditReader
{
    public async Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAsync(
        Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty || db.CurrentOrganizationId != organizationId)
            throw new UnauthorizedAccessException("Municipality audit context must match.");

        return await db.AuditEvents.AsNoTracking()
            .Where(x => x.OrganizationId == organizationId)
            .OrderByDescending(x => x.OccurredAt)
            .ThenByDescending(x => x.Id)
            .Take(25)
            .Select(x => new MunicipalAuditEntry(
                x.Id, x.Action, x.ResourceType, x.OccurredAt))
            .ToListAsync(cancellationToken);
    }
}

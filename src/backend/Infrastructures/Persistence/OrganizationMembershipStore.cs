using Comuni.Business.Organizations;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class OrganizationMembershipStore(ComuniDbContext db) : IOrganizationMembershipStore
{
    public async Task<IReadOnlyList<string>> ActiveRolesAsync(
        Guid organizationId, string subject, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty || string.IsNullOrWhiteSpace(subject))
            return [];

        return await db.OrganizationMemberships.AsNoTracking()
            .Where(x => x.OrganizationId == organizationId && x.Subject == subject && x.IsActive)
            .Select(x => x.Role)
            .OrderBy(x => x)
            .ToListAsync(cancellationToken);
    }
}

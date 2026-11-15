using Comuni.Business.Organizations;
using Comuni.Domains.Organizations;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class OrganizationDirectory(ComuniDbContext db) : IOrganizationDirectory, IOrganizationModuleStore
{
    public Task<Organization?> FindAsync(Guid organizationId, CancellationToken cancellationToken) =>
        db.Organizations.AsNoTracking().SingleOrDefaultAsync(x => x.Id == organizationId, cancellationToken);

    public async Task<IReadOnlyList<string>> EnabledModulesAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        return await db.OrganizationModules.AsNoTracking()
            .Where(m => m.OrganizationId == organizationId && m.Enabled)
            .Select(m => m.ModuleKey)
            .OrderBy(x => x)
            .ToListAsync(cancellationToken);
    }

    public Task<bool> IsEnabledAsync(Guid organizationId, string moduleKey, CancellationToken cancellationToken) =>
        db.OrganizationModules.AsNoTracking()
            .AnyAsync(m => m.OrganizationId == organizationId && m.ModuleKey == moduleKey && m.Enabled, cancellationToken);
}

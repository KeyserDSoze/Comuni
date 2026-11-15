using Comuni.Domains.Organizations;

namespace Comuni.Business.Organizations;

public interface IOrganizationDirectory
{
    Task<Organization?> FindAsync(Guid organizationId, CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> EnabledModulesAsync(Guid organizationId, CancellationToken cancellationToken);
}

public interface IOrganizationModuleStore
{
    Task<bool> IsEnabledAsync(Guid organizationId, string moduleKey, CancellationToken cancellationToken);
}

namespace Comuni.Business.Organizations;

/// <summary>
/// Authorization roles are retrieved from the database, never accepted from JWT role claims.
/// Subject must come from a validated token's sub claim.
/// </summary>
public interface IOrganizationMembershipStore
{
    Task<IReadOnlyList<string>> ActiveRolesAsync(Guid organizationId, string subject, CancellationToken cancellationToken);
}

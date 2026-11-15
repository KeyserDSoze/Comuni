using Comuni.Business.Organizations;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class OrganizationMembershipStore(ComuniDbContext db, MembershipIssuerPolicy issuerPolicy)
    : IOrganizationMembershipStore
{
    public async Task<IReadOnlyList<string>> ActiveRolesAsync(
        Guid organizationId, string subject, string? validatedIssuer, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty || string.IsNullOrWhiteSpace(subject))
            return [];

        // The OIDC identity is (iss, sub), not sub alone. An unbound/legacy
        // membership MUST NEVER authorize an OIDC access token.
        if (issuerPolicy.RequiresOidcBinding &&
            !MembershipIssuerPolicy.IsTrustedFormat(validatedIssuer))
            return [];

        var memberships = db.OrganizationMemberships.AsNoTracking()
            .Where(x => x.OrganizationId == organizationId && x.Subject == subject && x.IsActive);
        if (issuerPolicy.RequiresOidcBinding)
            memberships = memberships.Where(x => x.IdentityIssuer == validatedIssuer);

        return await memberships.Select(x => x.Role).OrderBy(x => x)
            .ToListAsync(cancellationToken);
    }
}

using Comuni.Business.Organizations;
using Microsoft.AspNetCore.Authorization;

namespace Comuni.Api.Security;

public sealed class OrganizationRoleHandler(IOrganizationMembershipStore memberships, IOrganizationDirectory organizations)
    : AuthorizationHandler<OrganizationRoleRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, OrganizationRoleRequirement requirement)
    {
        if (!VerifiedPrincipalIdentity.TryMunicipal(
                context.User, out var organizationId, out var subject, out var issuer))
            return;

        // A valid JWT and membership are insufficient for a suspended organization.
        if (!await organizations.IsOperationalAsync(organizationId, CancellationToken.None))
            return;

        var roles = await memberships.ActiveRolesAsync(organizationId, subject, issuer, CancellationToken.None);
        if (roles.Any(role => requirement.AllowedRoles.Contains(role, StringComparer.Ordinal)))
            context.Succeed(requirement);
    }
}

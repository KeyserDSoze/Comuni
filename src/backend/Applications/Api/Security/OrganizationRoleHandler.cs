using Comuni.Business.Organizations;
using Microsoft.AspNetCore.Authorization;

namespace Comuni.Api.Security;

public sealed class OrganizationRoleHandler(IOrganizationMembershipStore memberships, IOrganizationDirectory organizations)
    : AuthorizationHandler<OrganizationRoleRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, OrganizationRoleRequirement requirement)
    {
        var principal = context.User;
        if (principal.Identity?.IsAuthenticated != true ||
            !Guid.TryParse(principal.FindFirst("organization_id")?.Value, out var organizationId) ||
            organizationId == Guid.Empty)
            return;

        var subject = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(subject))
            return;

        // A valid JWT and membership are insufficient for a suspended organization.
        if (!await organizations.IsOperationalAsync(organizationId, CancellationToken.None))
            return;

        var roles = await memberships.ActiveRolesAsync(organizationId, subject, CancellationToken.None);
        if (roles.Any(role => requirement.AllowedRoles.Contains(role, StringComparer.Ordinal)))
            context.Succeed(requirement);
    }
}

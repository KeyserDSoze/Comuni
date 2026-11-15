using Comuni.Business.Organizations;
using Comuni.Business.Platform;
using Microsoft.AspNetCore.Authorization;

namespace Comuni.Api.Security;

public sealed class PlatformOperatorRequirement : IAuthorizationRequirement;

/// <summary>
/// Platform authorization is deliberately separate from organization RBAC.
/// No JWT role, group, organization_id, or development token grants access.
/// </summary>
public sealed class PlatformOperatorHandler(
    IPlatformOperatorStore operators, MembershipIssuerPolicy issuerPolicy)
    : AuthorizationHandler<PlatformOperatorRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, PlatformOperatorRequirement requirement)
    {
        if (!issuerPolicy.RequiresOidcBinding ||
            context.User.Identity?.IsAuthenticated != true ||
            context.User.HasClaim(claim => claim.Type == "organization_id"))
            return;

        var issuer = context.User.FindFirst("iss")?.Value;
        var subject = context.User.FindFirst("sub")?.Value;
        if (!MembershipIssuerPolicy.IsTrustedFormat(issuer) ||
            subject is not { Length: > 0 and <= 160 } ||
            subject != subject.Trim() || subject.Any(char.IsControl))
            return;

        if (await operators.IsActiveAsync(issuer!, subject, CancellationToken.None))
            context.Succeed(requirement);
    }
}

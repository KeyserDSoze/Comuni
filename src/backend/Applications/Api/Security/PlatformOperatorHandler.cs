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
            !VerifiedPrincipalIdentity.TryPlatform(context.User, out var issuer, out var subject) ||
            !MembershipIssuerPolicy.IsTrustedFormat(issuer))
            return;

        if (await operators.IsActiveAsync(issuer!, subject, CancellationToken.None))
            context.Succeed(requirement);
    }
}

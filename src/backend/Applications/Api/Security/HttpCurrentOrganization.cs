using Comuni.Business.Organizations;

namespace Comuni.Api.Security;

/// <summary>
/// A tenant is never accepted from the request body, route or custom header.
/// Authentication and authorization middleware validate the JWT first.
/// </summary>
public sealed class HttpCurrentOrganization(IHttpContextAccessor httpContextAccessor) : ICurrentOrganization
{
    public Guid OrganizationId
    {
        get
        {
            return VerifiedPrincipalIdentity.TryMunicipal(
                httpContextAccessor.HttpContext?.User, out var id, out _, out _)
                ? id : Guid.Empty;
        }
    }
}

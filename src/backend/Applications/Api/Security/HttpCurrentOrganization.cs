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
            var user = httpContextAccessor.HttpContext?.User;
            if (user?.Identity?.IsAuthenticated != true) return Guid.Empty;
            return Guid.TryParse(user.FindFirst("organization_id")?.Value, out var id) ? id : Guid.Empty;
        }
    }
}

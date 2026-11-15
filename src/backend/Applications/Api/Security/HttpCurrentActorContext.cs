using Comuni.Business.Audit;

namespace Comuni.Api.Security;

public sealed class HttpCurrentActorContext(IHttpContextAccessor accessor) : ICurrentActorContext
{
    public string ActorSubject
    {
        get
        {
            var user = accessor.HttpContext?.User;
            return user?.Identity?.IsAuthenticated == true
                ? user.FindFirst("sub")?.Value ?? string.Empty
                : string.Empty;
        }
    }

    public string? IdentityIssuer =>
        accessor.HttpContext?.User.Identity?.IsAuthenticated == true
            ? accessor.HttpContext.User.FindFirst("iss")?.Value : null;

    // ASP.NET Core allocates TraceIdentifier for the server request; do not trust X-Correlation-Id.
    public string CorrelationId => accessor.HttpContext?.TraceIdentifier ?? string.Empty;
}

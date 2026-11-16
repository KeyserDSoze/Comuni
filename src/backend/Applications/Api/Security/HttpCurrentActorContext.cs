using Comuni.Business.Audit;

namespace Comuni.Api.Security;

public sealed class HttpCurrentActorContext(IHttpContextAccessor accessor) : ICurrentActorContext
{
    // An audit actor MUST be the same single, validated identity used for
    // tenant authorization. A duplicate sub/issuer cannot become audit metadata.
    public string ActorSubject =>
        VerifiedPrincipalIdentity.TryMunicipal(
            accessor.HttpContext?.User, out _, out var subject, out _)
            ? subject : string.Empty;

    public string? IdentityIssuer =>
        VerifiedPrincipalIdentity.TryMunicipal(
            accessor.HttpContext?.User, out _, out _, out var issuer)
            ? issuer : null;

    // Server-generated request id; no X-Correlation-Id header is trusted.
    public string CorrelationId => accessor.HttpContext?.TraceIdentifier ?? string.Empty;
}

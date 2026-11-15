namespace Comuni.Business.Audit;

/// <summary>
/// Actor and request identifier supplied by the trusted, validated API request context.
/// Caller-supplied headers and JSON must never override these properties.
/// </summary>
public interface ICurrentActorContext
{
    string ActorSubject { get; }
    string CorrelationId { get; }

    // Only the verified JWT principal supplies this value in production.
    // Default null keeps isolated Business unit fakes independent of an HTTP host.
    string? IdentityIssuer => null;
}

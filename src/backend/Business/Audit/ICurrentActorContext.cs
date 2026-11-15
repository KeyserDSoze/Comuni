namespace Comuni.Business.Audit;

/// <summary>
/// Actor and request identifier supplied by the trusted, validated API request context.
/// Caller-supplied headers and JSON must never override these properties.
/// </summary>
public interface ICurrentActorContext
{
    string ActorSubject { get; }
    string CorrelationId { get; }
}

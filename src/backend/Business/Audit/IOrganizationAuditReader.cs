using Comuni.Domains.Audit;

namespace Comuni.Business.Audit;

/// <summary>
/// Minimal municipal event metadata only. Actor identity, resource ID,
/// correlation, organization identifier and document content stay server-side.
/// </summary>
public sealed record MunicipalAuditEntry(Guid Id, string Action,
    string ResourceType, DateTimeOffset OccurredAt);

public interface IOrganizationAuditReader
{
    Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAsync(
        Guid organizationId, CancellationToken cancellationToken);

    // An authenticated Admin HTTP read must append the consultation event
    // in the same signed RLS transaction, or fail without returning data.
    Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAndRecordAsync(
        Guid organizationId, AuditEvent consultation, CancellationToken cancellationToken);
}

/// <summary>
/// The use case builds the event from server-owned identity and correlation,
/// never user-provided query parameters or request headers.
/// </summary>
public sealed class MunicipalAuditService(IOrganizationAuditReader reader, ICurrentActorContext actor)
{
    public Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAsync(
        Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new UnauthorizedAccessException("Verified municipality is required.");

        var audit = AuditEvent.Create(
            organizationId, actor.ActorSubject, "platform.audit.consulted",
            "platform.audit", organizationId, actor.CorrelationId);
        return reader.ListRecentAndRecordAsync(organizationId, audit, cancellationToken);
    }
}

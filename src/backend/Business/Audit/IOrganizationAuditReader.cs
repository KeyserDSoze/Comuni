namespace Comuni.Business.Audit;

/// <summary>
/// Minimal municipal event metadata only. Actor identity, resource ID,
/// correlation, organization identifier and document content stay server-side.
/// </summary>
public sealed record MunicipalAuditEntry(Guid Id, string Action,
    string ResourceType, DateTimeOffset OccurredAt);

public interface IOrganizationAuditReader
{
    // No public unlogged reader: consultations must be appended atomically.

    // An authenticated Admin HTTP read must append the consultation event
    // in the same signed RLS transaction, or fail without returning data.
    Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAndRecordAsync(
        Guid organizationId, CancellationToken cancellationToken);
}

/// <summary>
/// Business verifies the tenant; Infrastructure constructs the event from
/// the scoped, verified server actor and correlation.
/// </summary>
public sealed class MunicipalAuditService(IOrganizationAuditReader reader)
{
    public Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAsync(
        Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new UnauthorizedAccessException("Verified municipality is required.");

        return reader.ListRecentAndRecordAsync(organizationId, cancellationToken);
    }
}

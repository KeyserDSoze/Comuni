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
}

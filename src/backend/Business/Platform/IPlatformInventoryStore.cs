namespace Comuni.Business.Platform;

/// <summary>
/// Administrative metadata only. Never include members, documents or
/// organization-scoped records in the platform inventory projection.
/// </summary>
public sealed record PlatformOrganizationItem(
    Guid Id, string Name, bool IsSuspended, bool ProtocolEnabled, string LifecycleStatus);

public sealed record PlatformInventoryPage(
    IReadOnlyList<PlatformOrganizationItem> Organizations, Guid? NextCursor);

public interface IPlatformInventoryStore
{
    Task<PlatformInventoryPage> ListAsync(
        string issuer, string subject, int pageSize, Guid? after,
        CancellationToken cancellationToken);
}

using Comuni.Business.Audit;
using Comuni.Domains.Audit;

namespace Comuni.Business.Organizations;

public sealed record ModuleState(string Key, bool Enabled);
public enum ModuleUpdateStatus { NotFound, Unchanged, Updated }

public interface IModuleAdministrationStore
{
    Task<IReadOnlyList<ModuleState>> ListAsync(Guid organizationId, CancellationToken cancellationToken);
    Task<ModuleUpdateStatus> SetEnabledAsync(Guid organizationId, string moduleKey,
        bool enabled, AuditEvent audit, CancellationToken cancellationToken);
}

/// <summary>
/// Core admin use case. The current slice manages only the installed Protocol module.
/// Authentication/authorization policy is enforced by the API; the store is tenant-scoped.
/// </summary>
public sealed class ModuleAdministrationService(
    IModuleAdministrationStore store, ICurrentActorContext actor)
{
    public Task<IReadOnlyList<ModuleState>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization context is required.", nameof(organizationId));
        return store.ListAsync(organizationId, cancellationToken);
    }

    public Task<ModuleUpdateStatus> SetEnabledAsync(
        Guid organizationId, string moduleKey, bool enabled, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization context is required.", nameof(organizationId));

        // Whitelist is backend-owned, never driven by moduleKey supplied by the client.
        if (!string.Equals(moduleKey, "protocol", StringComparison.Ordinal))
            return Task.FromResult(ModuleUpdateStatus.NotFound);

        var audit = AuditEvent.Create(
            organizationId, actor.ActorSubject,
            enabled ? "platform.module.protocol.enabled" : "platform.module.protocol.disabled",
            "platform.module", organizationId, actor.CorrelationId);
        return store.SetEnabledAsync(organizationId, "protocol", enabled, audit, cancellationToken);
    }
}

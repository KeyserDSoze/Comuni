using Comuni.Business.Organizations;
using Comuni.Business.Audit;
using Comuni.Domains.Audit;
using Comuni.Domains.Protocol;

namespace Comuni.Business.Protocol;

public sealed class ModuleDisabledException(string moduleKey) :
    InvalidOperationException($"Module '{moduleKey}' is not enabled for this organization.");

public sealed class ProtocolService(IProtocolRepository repository, IOrganizationModuleStore modules, ICurrentActorContext actor)
{
    public async Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        await EnsureEnabledAsync(organizationId, cancellationToken);
        return await repository.ListAsync(organizationId, cancellationToken);
    }

    public async Task<ProtocolRecord> RegisterAsync(Guid organizationId, string subject, CancellationToken cancellationToken)
    {
        await EnsureEnabledAsync(organizationId, cancellationToken);
        var record = ProtocolRecord.Register(organizationId, subject);
        var audit = AuditEvent.Create(organizationId, actor.ActorSubject,
            "protocol.record.created", "protocol.record", record.Id, actor.CorrelationId);
        await repository.AddAsync(record, audit, cancellationToken);
        return record;
    }

    private async Task EnsureEnabledAsync(Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty ||
            !await modules.IsEnabledAsync(organizationId, "protocol", cancellationToken))
        {
            throw new ModuleDisabledException("protocol");
        }
    }
}

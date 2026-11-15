using Comuni.Domains.Protocol;
using Comuni.Domains.Audit;

namespace Comuni.Business.Protocol;

public interface IProtocolRepository
{
    Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken);
    Task AddAsync(ProtocolRecord record, AuditEvent audit, CancellationToken cancellationToken);
}

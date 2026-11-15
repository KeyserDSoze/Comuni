using Comuni.Domains.Protocol;

namespace Comuni.Business.Protocol;

public interface IProtocolRepository
{
    Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken cancellationToken);
    Task AddAsync(ProtocolRecord record, CancellationToken cancellationToken);
}

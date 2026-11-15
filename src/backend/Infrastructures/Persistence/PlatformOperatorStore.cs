using Comuni.Business.Platform;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Invoke the narrowly granted security-definer predicate. The runtime SQL
/// role MUST NOT have SELECT permission on platform.platform_operators.
/// </summary>
public sealed class PlatformOperatorStore(ComuniDbContext db) : IPlatformOperatorStore
{
    public Task<bool> IsActiveAsync(
        string validatedIssuer, string subject, CancellationToken cancellationToken) =>
        db.Database.SqlQuery<bool>(
            $"SELECT platform.is_active_platform_operator({validatedIssuer}, {subject}) AS \"Value\"")
            .SingleAsync(cancellationToken);
}

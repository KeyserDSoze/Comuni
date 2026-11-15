using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Creates a PostgreSQL transaction and a transaction-local tenant setting (SET LOCAL).
/// The runtime DB role uses RLS policies on this setting. Always dispose the transaction:
/// a pooled database connection must never retain a session-scoped tenant.
/// </summary>
public static class TenantDatabaseTransaction
{
    public static async Task<IDbContextTransaction> BeginAsync(
        ComuniDbContext db, CancellationToken cancellationToken)
    {
        var organizationId = db.CurrentOrganizationId;
        if (organizationId == Guid.Empty)
            throw new UnauthorizedAccessException("A verified organization is required.");

        if (db.Database.CurrentTransaction is not null)
            throw new InvalidOperationException("A PostgreSQL tenant transaction is already active.");

        var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            // The third argument makes this SET LOCAL, automatically cleared on commit/rollback.
            // Interpolated SQL is parameterized; the organization comes from the JWT principal.
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT set_config('comuni.organization_id', {organizationId.ToString("D")}, true)",
                cancellationToken);
            return transaction;
        }
        catch
        {
            await transaction.DisposeAsync();
            throw;
        }
    }
}

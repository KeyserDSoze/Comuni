using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Tests the signer of this API revision against the existing PostgreSQL RLS
/// verifier, never querying tenant data or storing a synthetic organization.
/// </summary>
public static class TenantRlsReadinessProbe
{
    public static async Task<bool> CheckAsync(
        ComuniDbContext db, TenantProofSigner signer, CancellationToken cancellationToken)
    {
        try
        {
            var syntheticOrganization = Guid.NewGuid();
            // A corrupted MAC must be rejected, not merely a correct MAC
            // accepted. This also catches an accidentally permissive verifier.
            var signed = signer.Create(syntheticOrganization);
            var forged = signed[..^1] + (signed[^1] == '0' ? '1' : '0');

            await using var transaction =
                await db.Database.BeginTransactionAsync(cancellationToken);

            async Task<object?> VerifyAsync(string proof)
            {
                // Npgsql binds the token, never interpolates it as SQL text.
                // SET LOCAL expires on rollback, including pooled connections.
                await db.Database.ExecuteSqlInterpolatedAsync(
                    $"SELECT set_config('comuni.tenant_assertion', {proof}, true)",
                    cancellationToken);
                await using var command = db.Database.GetDbConnection().CreateCommand();
                command.Transaction = transaction.GetDbTransaction();
                command.CommandText = "SELECT platform.verified_tenant_id()";
                return await command.ExecuteScalarAsync(cancellationToken);
            }

            var denied = await VerifyAsync(forged);
            if (denied is not null && denied != DBNull.Value)
                return false;

            var accepted = await VerifyAsync(signed);
            await transaction.RollbackAsync(cancellationToken);
            return accepted is Guid verified && verified == syntheticOrganization;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Probe failures are 503, never raw DB errors or credential hints.
            return false;
        }
    }
}

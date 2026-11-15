using System.Data;
using Comuni.Business.Platform;
using Npgsql;
using NpgsqlTypes;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Uses a DEDICATED restricted PostgreSQL login; never the municipal tenant
/// DbContext, SQL role, signed RLS proof or EF IgnoreQueryFilters.
/// </summary>
public sealed class PlatformInventoryStore(string platformReadConnection)
    : IPlatformInventoryStore
{
    public async Task<PlatformInventoryPage> ListAsync(
        string issuer, string subject, int pageSize, Guid? after,
        CancellationToken cancellationToken)
    {
        if (pageSize is < 1 or > 25)
            throw new ArgumentOutOfRangeException(nameof(pageSize));

        await using var db = new NpgsqlConnection(platformReadConnection);
        await db.OpenAsync(cancellationToken);
        // Read authorization, inventory and append-only audit belong to ONE
        // transaction. A failure cannot return data without an audit event.
        await using var transaction =
            await db.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);

        Guid actor;
        await using (var verified = new NpgsqlCommand(
            "SELECT platform.active_platform_operator_id(@iss, @sub)", db, transaction))
        {
            verified.Parameters.AddWithValue("iss", issuer);
            verified.Parameters.AddWithValue("sub", subject);
            var value = await verified.ExecuteScalarAsync(cancellationToken);
            if (value is not Guid verifiedActor || verifiedActor == Guid.Empty)
                throw new UnauthorizedAccessException("Platform operator is no longer active.");
            actor = verifiedActor;
        }

        var items = new List<PlatformOrganizationItem>(pageSize + 1);
        await using (var select = new NpgsqlCommand("""
            SELECT id, name, is_suspended, protocol_enabled
            FROM platform.platform_organization_inventory
            WHERE (@after IS NULL OR id > @after)
            ORDER BY id
            LIMIT @take
            """, db, transaction))
        {
            select.Parameters.Add(new NpgsqlParameter("after", NpgsqlDbType.Uuid)
            {
                Value = (object?)after ?? DBNull.Value
            });
            select.Parameters.AddWithValue("take", pageSize + 1);
            await using var rows = await select.ExecuteReaderAsync(cancellationToken);
            while (await rows.ReadAsync(cancellationToken))
            {
                items.Add(new PlatformOrganizationItem(
                    rows.GetGuid(0), rows.GetString(1),
                    rows.GetBoolean(2), rows.GetBoolean(3)));
            }
        }

        Guid? nextCursor = null;
        if (items.Count > pageSize)
        {
            items.RemoveAt(pageSize);
            nextCursor = items[^1].Id;
        }

        await using (var audit = new NpgsqlCommand("""
            INSERT INTO platform.platform_operator_audit_events
                (id, actor_subject, action, resource_type, resource_id,
                 correlation_id, occurred_at)
            VALUES (@id, 'platform-operator', 'platform.organizations.listed',
                    'platform.organization-inventory', @operator,
                    @correlation, now())
            """, db, transaction))
        {
            audit.Parameters.AddWithValue("id", Guid.NewGuid());
            audit.Parameters.AddWithValue("operator", actor);
            audit.Parameters.AddWithValue("correlation", "inventory:" + Guid.NewGuid().ToString("N"));
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return new PlatformInventoryPage(items, nextCursor);
    }
}

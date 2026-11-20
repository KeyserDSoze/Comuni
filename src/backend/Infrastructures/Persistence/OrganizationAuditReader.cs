using Comuni.Business.Audit;
using Comuni.Domains.Audit;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Must be run inside the signed, transaction-scoped tenant proof established
/// by the API. Never IgnoreQueryFilters or use the schema-owner connection.
/// PostgreSQL grants SELECT on only the five columns needed for filtering and
/// projection; actor, correlation and resource identifiers are not readable.
/// </summary>
public sealed class OrganizationAuditReader(ComuniDbContext db, ICurrentActorContext actor) : IOrganizationAuditReader
{
    private async Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAsync(
        Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty || db.CurrentOrganizationId != organizationId)
            throw new UnauthorizedAccessException("Municipality audit context must match.");

        return await db.AuditEvents.AsNoTracking()
            .Where(x => x.OrganizationId == organizationId)
            .OrderByDescending(x => x.OccurredAt)
            .ThenByDescending(x => x.Id)
            .Take(25)
            .Select(x => new MunicipalAuditEntry(
                x.Id, x.Action, x.ResourceType, x.OccurredAt))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Requires an existing verified tenant SQL transaction, established by the
    /// API middleware. No implicit unscoped transaction, owner fallback or
    /// reader response without a durable audit append is permitted.
    /// </summary>
    public async Task<IReadOnlyList<MunicipalAuditEntry>> ListRecentAndRecordAsync(
        Guid organizationId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty ||
            db.CurrentOrganizationId != organizationId)
            throw new UnauthorizedAccessException("Municipal audit scope mismatch.");

        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("Signed tenant audit transaction is required.");

        // Capture the response BEFORE appending this consultation. The request
        // never reports its own event; the next authorized read may see it.
        // Caller cannot submit an event with forged actor/correlation.
        // Invalid actor metadata fails before the sensitive SELECT.
        var consultation = AuditEvent.Create(
            organizationId, actor.ActorSubject, "platform.audit.consulted",
            "platform.audit", organizationId, actor.CorrelationId);
        var entries = await ListRecentAsync(organizationId, cancellationToken);
        await db.AuditEvents.AddAsync(consultation, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        // The tenant middleware commits only successful HTTP requests. If
        // response processing fails, disposal rolls back both operations.
        return entries;
    }
}

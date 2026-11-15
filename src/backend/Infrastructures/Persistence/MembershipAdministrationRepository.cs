using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Atomic PostgreSQL upsert with unique composite PK and append-only audit
/// in the SAME request transaction. Tenant is only from the validated context.
/// </summary>
public sealed class MembershipAdministrationRepository(ComuniDbContext db, TenantProofSigner signer,
    MembershipIssuerPolicy issuerPolicy)
    : IMembershipAdministrationStore
{
    public async Task<IReadOnlyList<MembershipState>> ListAsync(Guid organizationId, CancellationToken ct) =>
        await db.OrganizationMemberships.AsNoTracking()
            .Where(x => x.OrganizationId == organizationId)
            .OrderBy(x => x.Subject).ThenBy(x => x.Role)
            .Select(x => new MembershipState(x.Subject, x.Role, x.IsActive, x.IdentityIssuer))
            .ToListAsync(ct);

    public async Task<MembershipUpdateStatus> SetActiveAsync(
        Guid organizationId, string subject, string role,
        bool enabled, string? validatedIssuer, AuditEvent audit, CancellationToken ct)
    {
        if (organizationId == Guid.Empty || db.CurrentOrganizationId != organizationId ||
            audit.OrganizationId != organizationId ||
            role is not ("Reader" or "Officer") ||
            (issuerPolicy.RequiresOidcBinding &&
                !MembershipIssuerPolicy.IsTrustedFormat(validatedIssuer)))
            throw new UnauthorizedAccessException("Cannot edit memberships outside the authorized tenant/roles.");

        // Demo values remain unbound and never turn into OIDC entitlements.
        var identityIssuer = issuerPolicy.RequiresOidcBinding ? validatedIssuer : null;

        var ownsTransaction = db.Database.CurrentTransaction is null;
        await using var transaction = ownsTransaction
            ? await TenantDatabaseTransaction.BeginAsync(db, signer, ct)
            : null;

        // Parameterized and concurrency-safe. The unique key prevents duplicates.
        // SQL RLS *RESTRICTIVE* policy rejects Admin writes even if API code is bypassed.
        int changed;
        if (enabled)
        {
            changed = await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO platform.organization_memberships
                    (organization_id, subject, role, is_active, identity_issuer)
                VALUES ({organizationId}, {subject}, {role}, TRUE, {identityIssuer})
                ON CONFLICT (organization_id, subject, role)
                DO UPDATE SET is_active = TRUE
                WHERE organization_memberships.identity_issuer IS NOT DISTINCT FROM EXCLUDED.identity_issuer
                  AND organization_memberships.is_active IS DISTINCT FROM TRUE
                """, ct);
        }
        else
        {
            changed = await db.Database.ExecuteSqlInterpolatedAsync($"""
                UPDATE platform.organization_memberships
                SET is_active = FALSE
                WHERE organization_id = {organizationId}
                  AND subject = {subject} AND role = {role}
                  AND identity_issuer IS NOT DISTINCT FROM {identityIssuer}
                  AND is_active = TRUE
                """, ct);
        }

        if (changed == 0)
        {
            var existing = await db.OrganizationMemberships.AsNoTracking()
                .Where(x => x.OrganizationId == organizationId &&
                    x.Subject == subject && x.Role == role)
                .Select(x => new { x.IdentityIssuer }).SingleOrDefaultAsync(ct);
            if (existing is null)
                return enabled
                    ? throw new InvalidOperationException("Membership upsert unexpectedly failed.")
                    : MembershipUpdateStatus.NotFound;
            if (!string.Equals(existing.IdentityIssuer, identityIssuer, StringComparison.Ordinal))
                return MembershipUpdateStatus.IssuerConflict;
            return MembershipUpdateStatus.Unchanged;
        }

        await db.AuditEvents.AddAsync(audit, ct);
        await db.SaveChangesAsync(ct);
        if (transaction is not null)
            await transaction.CommitAsync(ct);
        return MembershipUpdateStatus.Updated;
    }
}

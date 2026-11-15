using System.Security.Cryptography;
using System.Text;
using Comuni.Business.Audit;
using Comuni.Domains.Audit;
using Comuni.Domains.Organizations;

namespace Comuni.Business.Organizations;

public sealed record MembershipState(string Subject, string Role, bool Enabled);
public enum MembershipUpdateStatus { NotFound, Unchanged, Updated }

public interface IMembershipAdministrationStore
{
    Task<IReadOnlyList<MembershipState>> ListAsync(Guid organizationId, CancellationToken ct);
    Task<MembershipUpdateStatus> SetActiveAsync(Guid organizationId, string subject,
        string role, bool enabled, AuditEvent audit, CancellationToken ct);
}

/// <summary>
/// Tenant Admin may pre-provision/revoke Reader and Officer only.
/// Identity is issued by an external IdP; this use case NEVER creates users,
/// tokens, or Admin roles. PostgreSQL RLS enforces the same role restriction.
/// </summary>
public sealed class MembershipAdministrationService(
    IMembershipAdministrationStore store, ICurrentActorContext actor)
{
    public Task<IReadOnlyList<MembershipState>> ListAsync(Guid organizationId, CancellationToken ct)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("A verified organization is required.", nameof(organizationId));
        return store.ListAsync(organizationId, ct);
    }

    public Task<MembershipUpdateStatus> SetActiveAsync(
        Guid organizationId, string subject, string role, bool enabled, CancellationToken ct)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("A verified organization is required.", nameof(organizationId));
        if (role is not ("Reader" or "Officer"))
            throw new ArgumentException("Only Reader/Officer roles are managed here.", nameof(role));

        // OIDC 'sub' identifiers are case sensitive; never normalize them.
        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 160 ||
            !string.Equals(subject, subject.Trim(), StringComparison.Ordinal) ||
            subject.Any(char.IsControl))
            throw new ArgumentException("Subject must be 1-160 non-control characters without outer whitespace.",
                nameof(subject));
        _ = OrganizationMembership.Grant(organizationId, subject, role);

        // A stable pseudonymous audit resource id references this specific
        // membership without storing the external subject in the audit payload.
        // This is a deterministic identifier, NOT an anonymization guarantee.
        var hashed = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{organizationId:D}|{role}|{subject}"));
        var resourceId = new Guid(hashed.AsSpan(0, 16));
        var audit = AuditEvent.Create(organizationId, actor.ActorSubject,
            $"platform.membership.{role.ToLowerInvariant()}.{(enabled ? "activated" : "deactivated")}",
            "platform.membership", resourceId, actor.CorrelationId);
        return store.SetActiveAsync(organizationId, subject, role, enabled, audit, ct);
    }
}

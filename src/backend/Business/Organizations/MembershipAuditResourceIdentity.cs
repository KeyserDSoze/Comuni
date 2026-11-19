using System.Security.Cryptography;
using System.Text;

namespace Comuni.Business.Organizations;

/// <summary>
/// Stable pseudonymous audit resource ID for an exact issuer-bound membership.
/// This must stay byte-for-byte compatible with the original ADR 0021 format.
/// Pseudonymization is NOT anonymization: source identity remains protected data.
/// </summary>
public static class MembershipAuditResourceIdentity
{
    public static Guid Create(Guid organizationId, string role, string subject, string? identityIssuer)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{organizationId:D}|{role}|{subject}|{identityIssuer ?? ""}"));
        return new Guid(hash.AsSpan(0, 16));
    }
}

namespace Comuni.Domains.Organizations;

/// <summary>
/// A subject's role in one organization. Identity is external; memberships are server-owned.
/// </summary>
public sealed class OrganizationMembership
{
    private OrganizationMembership() { } // EF Core

    private OrganizationMembership(Guid organizationId, string subject, string role, string? identityIssuer)
    {
        OrganizationId = organizationId;
        Subject = subject;
        Role = role;
        IdentityIssuer = identityIssuer;
        IsActive = true;
    }

    public Guid OrganizationId { get; private set; }
    public string Subject { get; private set; } = string.Empty;
    public string Role { get; private set; } = string.Empty;
    public bool IsActive { get; private set; }
    // Null is a legacy/demo-only membership. It NEVER authorizes production OIDC JWTs.
    public string? IdentityIssuer { get; private set; }

    public static OrganizationMembership Grant(Guid organizationId, string subject, string role, string? identityIssuer = null)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization ID is required.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(subject) || subject.Trim().Length > 160)
            throw new ArgumentException("Subject must be 1-160 characters.", nameof(subject));
        if (role is not ("Admin" or "Officer" or "Reader"))
            throw new ArgumentException("Unknown organization role.", nameof(role));

        if (identityIssuer is not null &&
            !(Uri.TryCreate(identityIssuer, UriKind.Absolute, out var uri) &&
              uri.Scheme == Uri.UriSchemeHttps && identityIssuer.Length <= 512 &&
              string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) &&
              string.IsNullOrEmpty(uri.Fragment)))
            throw new ArgumentException("Identity issuer must be an absolute HTTPS URL.", nameof(identityIssuer));
        return new OrganizationMembership(organizationId, subject.Trim(), role, identityIssuer);
    }

    public void Deactivate() => IsActive = false;
    public void Activate() => IsActive = true;
}

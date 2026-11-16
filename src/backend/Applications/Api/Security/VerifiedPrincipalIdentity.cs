using System.Security.Claims;

namespace Comuni.Api.Security;

/// <summary>
/// One interpretation of validated JWT identity claims for the entire API.
/// JWT signature/issuer/audience/lifetime validation occurs in JwtBearer.
/// Here authorization, signed RLS, audit and rate limiting all refuse *any*
/// missing or duplicate org/sub/iss instead of selecting FindFirst arbitrarily.
/// </summary>
public static class VerifiedPrincipalIdentity
{
    public static bool TryMunicipal(ClaimsPrincipal? user, out Guid organizationId,
        out string subject, out string issuer)
    {
        organizationId = Guid.Empty;
        subject = string.Empty;
        issuer = string.Empty;
        if (user?.Identity?.IsAuthenticated != true ||
            !TrySingle(user, "organization_id", out var organization) ||
            !TrySingle(user, "sub", out var rawSubject) ||
            !TrySingle(user, "iss", out var rawIssuer) ||
            !Guid.TryParse(organization, out var parsedOrganization) ||
            parsedOrganization == Guid.Empty ||
            !ValidSubject(rawSubject) || !ValidIssuer(rawIssuer))
            return false;

        organizationId = parsedOrganization;
        subject = rawSubject;
        issuer = rawIssuer;
        return true;
    }

    public static bool TryPlatform(ClaimsPrincipal? user, out string issuer, out string subject)
    {
        issuer = string.Empty;
        subject = string.Empty;
        // Platform access is tenantless and uses independently provisioned
        // issuer+subject; no municipal organization claim may be present.
        if (user?.Identity?.IsAuthenticated != true ||
            user.HasClaim(claim => claim.Type == "organization_id") ||
            !TrySingle(user, "iss", out var rawIssuer) ||
            !TrySingle(user, "sub", out var rawSubject) ||
            !ValidIssuer(rawIssuer) || !ValidSubject(rawSubject))
            return false;

        issuer = rawIssuer;
        subject = rawSubject;
        return true;
    }

    private static bool TrySingle(ClaimsPrincipal user, string type, out string value)
    {
        value = string.Empty;
        // Two identical claims are ambiguous too: never collapse duplicates.
        using var claims = user.FindAll(type).GetEnumerator();
        if (!claims.MoveNext()) return false;
        var candidate = claims.Current.Value;
        if (claims.MoveNext() || string.IsNullOrWhiteSpace(candidate))
            return false;
        value = candidate;
        return true;
    }

    private static bool ValidSubject(string value) =>
        value.Length <= 160 && value == value.Trim() &&
        !value.Any(char.IsControl);

    private static bool ValidIssuer(string value) =>
        value.Length <= 512 && value == value.Trim() &&
        !value.Any(char.IsControl);
}

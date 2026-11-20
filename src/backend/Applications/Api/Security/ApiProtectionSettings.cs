using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Comuni.Api.Security;

/// <summary>
/// Per-replica API protection policy. The partition is based only on an already-validated
/// principal or the connection's actual peer IP. Untrusted forwarding headers are ignored.
/// </summary>
public sealed record ApiProtectionSettings(int PermitLimit, int WindowSeconds)
{
    public static ApiProtectionSettings Read(IConfiguration configuration)
    {
        var permitLimit = ReadInt(configuration, "Security:ApiRateLimit:PermitLimit", 120, 1, 10000);
        var windowSeconds = ReadInt(configuration, "Security:ApiRateLimit:WindowSeconds", 60, 1, 3600);
        return new ApiProtectionSettings(permitLimit, windowSeconds);
    }

    private static int ReadInt(IConfiguration config, string key, int fallback, int min, int max)
    {
        var raw = config[key];
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            value < min || value > max)
            throw new InvalidOperationException($"{key} must be an integer between {min} and {max}.");
        return value;
    }

    public static string PartitionKey(HttpContext context)
    {
        if (VerifiedPrincipalIdentity.TryMunicipal(
                context.User, out var organizationId, out var subject, out var issuer))
            return Fingerprint("tenant", organizationId.ToString("N"), issuer, subject);

        // Platform operators carry an issuer+subject but *no* organization.
        // This rate-limit bucket is NOT platform authorization; the
        // PlatformOperatorHandler still checks the DB-backed operator roster.
        if (VerifiedPrincipalIdentity.TryPlatform(
                context.User, out var platformIssuer, out var platformSubject))
            return Fingerprint("platform", string.Empty, platformIssuer, platformSubject);

        // Invalid, ambiguous and anonymous principals share a bucket based
        // solely on the real connection peer, not X-Forwarded-For.
        return $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
    }

    private static string Fingerprint(string scope, string organization,
        string issuer, string subject)
    {
        // Exact, case-sensitive issuer/subject identity. Length prefixes
        // prevent concatenation collisions even when OIDC subjects contain
        // the same delimiters as an issuer or organization. The scope prefix
        // separates municipal from tenantless platform quota namespaces.
        // SHA-256 avoids placing raw subjects/issuers in limiter keys. It is
        // NOT encryption or an anonymization guarantee if a key were leaked.
        var identity = $"{organization.Length}:{organization}" +
                       $"{issuer.Length}:{issuer}{subject.Length}:{subject}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        return scope + ":" + Convert.ToHexStringLower(digest);
    }

    public static void ApplyResponseHeaders(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        headers["Content-Security-Policy"] =
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; " +
            "form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'";

        if (context.Request.Path.StartsWithSegments("/api") ||
            string.Equals(context.Request.Path.Value, "/health/ready",
                StringComparison.OrdinalIgnoreCase))
        {
            headers["Cache-Control"] = "no-store";
            headers["Pragma"] = "no-cache";
        }
    }
}

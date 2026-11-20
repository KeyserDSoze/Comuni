using System.Globalization;
using System.Security.Claims;
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
                context.User, out var organizationId, out var subject, out _))
            return $"tenant:{organizationId:N}:{subject}";

        // Never trust X-Forwarded-For without a configured, trusted proxy boundary.
        return $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
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

using Npgsql;

namespace Comuni.Api.Security;

/// <summary>
/// This feature is OFF until a separate restricted platform-read SQL login
/// and an explicit connection string are provisioned. Never fall back to
/// the municipal runtime or owner database connection.
/// </summary>
public sealed record PlatformInventorySettings(bool Enabled, string? ConnectionString)
{
    public static PlatformInventorySettings Read(
        IConfiguration configuration, string authenticationMode, string defaultConnection,
        string environmentName)
    {
        var raw = configuration["PlatformInventory:Enabled"];
        if (raw is not (null or "false" or "False" or "true" or "True"))
            throw new InvalidOperationException("PlatformInventory:Enabled must be a boolean.");
        if (!string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase))
            return new PlatformInventorySettings(false, null);

        if (authenticationMode != "Oidc")
            throw new InvalidOperationException("Platform inventory requires OIDC authentication.");

        var platformConnection = configuration.GetConnectionString("PlatformRead");
        if (string.IsNullOrWhiteSpace(platformConnection))
            throw new InvalidOperationException("ConnectionStrings:PlatformRead is required for inventory.");

        // These checks are deliberately BEFORE the first DB query.
        var reader = new NpgsqlConnectionStringBuilder(platformConnection);
        var normal = new NpgsqlConnectionStringBuilder(defaultConnection);
        if (reader.Username != "comuni_platform_reader" ||
            reader.Username == normal.Username ||
            string.IsNullOrWhiteSpace(reader.Password) ||
            reader.Database != normal.Database ||
            !string.Equals(reader.Host, normal.Host, StringComparison.OrdinalIgnoreCase) ||
            reader.Port != normal.Port)
            throw new InvalidOperationException("Platform inventory needs its own least-privilege login on the same PostgreSQL database.");

        // Global platform credentials can enumerate ALL municipality metadata.
        // In hosted environments, encryption alone is insufficient: reject a
        // TLS peer whose CA or hostname was not verified. No implicit fallback
        // to Require/VerifyCA or Trust Server Certificate=true.
        if (environmentName is not ("Development" or "Testing") &&
            (reader.SslMode != SslMode.VerifyFull || reader.TrustServerCertificate))
            throw new InvalidOperationException(
                "Platform inventory requires full PostgreSQL server certificate and hostname verification.");

        return new PlatformInventorySettings(true, platformConnection);
    }
}

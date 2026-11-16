using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Comuni.Api.Security;

/// <summary>
/// Validates the municipal PostgreSQL RLS runtime connection before registering
/// EF Core, opening a socket, or accepting any tenant request. Azure-only hosted
/// revisions must verify BOTH the server certificate chain and DNS identity.
/// </summary>
public static class RuntimePostgresConnectionSettings
{
    // Azure Database for PostgreSQL Flexible Server's public service FQDN is
    // also used with VNet/private DNS. Do not accept IPs, localhost, aliases,
    // multi-host strings, or arbitrary lookalike suffixes in hosted revisions.
    private static readonly Regex AzurePostgresHost = new(
        @"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.postgres\.database\.azure\.com$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    public static string Read(IConfiguration configuration, string environmentName)
    {
        var connection = configuration.GetConnectionString("Default");
        if (string.IsNullOrWhiteSpace(connection))
            throw new InvalidOperationException("ConnectionStrings:Default is required.");

        // A disposable PostgreSQL 17 test database / local Docker Compose does
        // not require an Azure FQDN or a production certificate authority.
        if (environmentName is "Development" or "Testing")
            return connection;

        NpgsqlConnectionStringBuilder settings;
        try
        {
            settings = new NpgsqlConnectionStringBuilder(connection);
        }
        catch (Exception error) when (error is ArgumentException or FormatException
                                      or NotSupportedException)
        {
            // Npgsql errors can include the original connection string.
            // Never echo connection data or an inner exception to logs.
            throw new InvalidOperationException(
                "ConnectionStrings:Default must be a valid PostgreSQL connection.");
        }

        if (settings.SslMode != SslMode.VerifyFull || settings.TrustServerCertificate)
            throw new InvalidOperationException(
                "ConnectionStrings:Default requires PostgreSQL TLS certificate and hostname verification.");

        // This is independent ARM/Terraform metadata, not part of the
        // Key Vault connection secret. An attacker-controlled *different*
        // Azure PostgreSQL server has a perfectly valid TLS certificate.
        var expectedHost = configuration["RuntimePostgres:ExpectedHost"];
        if (string.IsNullOrWhiteSpace(expectedHost) ||
            !AzurePostgresHost.IsMatch(expectedHost) ||
            !string.Equals(settings.Host, expectedHost, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "RuntimePostgres:ExpectedHost does not match the authorized Azure PostgreSQL server.");

        if (settings.Username != "comuni_app_runtime" ||
            string.IsNullOrWhiteSpace(settings.Password) ||
            string.IsNullOrWhiteSpace(settings.Database) ||
            settings.Port != 5432 ||
            !AzurePostgresHost.IsMatch(settings.Host ?? string.Empty))
            throw new InvalidOperationException(
                "ConnectionStrings:Default must use the restricted municipal runtime principal and Azure PostgreSQL FQDN.");

        // Return the original value without serializing/logging parsed secrets.
        // Real CA trust, PostgreSQL grants and DNS still require Azure smoke.
        return connection;
    }
}

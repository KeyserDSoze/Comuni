using Comuni.Api.Security;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first: production tenant RLS SQL credentials must be sent only to a
/// verified Azure PostgreSQL Flexible Server hostname. Entirely synthetic.
/// </summary>
public sealed class RuntimePostgresConnectionSettingsTests
{
    private const string Secret = "synthetic-postgres-password-do-not-log";
    private const string Valid =
        "Host=comuni-itn-001-pg.postgres.database.azure.com;Port=5432;Database=comuni;" +
        "Username=comuni_app_runtime;Password=" + Secret +
        ";SSL Mode=VerifyFull;Trust Server Certificate=false";

    private static IConfiguration Config(string? value) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ConnectionStrings:Default"] = value }).Build();

    private static string Read(string? value, string environmentName) =>
        RuntimePostgresConnectionSettings.Read(Config(value), environmentName);

    private static void Reject(string? value, string environmentName = "Production")
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Read(value, environmentName));
        Assert.DoesNotContain(Secret, ex.Message);
        Assert.DoesNotContain("comuni-itn-001-pg", ex.Message);
        Assert.DoesNotContain("Password=", ex.Message);
        Assert.DoesNotContain(value ?? "not-provided-synthetic", ex.Message);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Preview")]
    [InlineData("CustomHostedEnvironment")]
    public void Hosted_accepts_only_verified_azure_server_and_runtime_role(string environmentName)
    {
        var result = Read(Valid, environmentName);
        Assert.Equal(Valid, result);
    }

    [Theory]
    [InlineData("Disable")]
    [InlineData("Allow")]
    [InlineData("Prefer")]
    [InlineData("Require")]
    [InlineData("VerifyCA")]
    public void Production_rejects_tls_modes_without_full_certificate_and_hostname_verification(string mode)
    {
        Reject(Valid.Replace("SSL Mode=VerifyFull", "SSL Mode=" + mode, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Preview")]
    public void Hosted_rejects_bypass_even_with_verify_full(string environmentName)
    {
        Reject(Valid.Replace("Trust Server Certificate=false", "Trust Server Certificate=true",
            StringComparison.Ordinal), environmentName);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("10.90.2.3")]
    [InlineData("evil.example.test")]
    [InlineData("comuni-itn-001-pg.postgres.database.azure.com.evil.test")]
    [InlineData("comuni-itn-001-pg.private.postgres.database.azure.com")]
    [InlineData("comuni-itn-001-pg.postgres.database.azure.com,evil.example.test")]
    [InlineData("postgres.database.azure.com")]
    [InlineData("comuni-itn-001-pg.postgres.database.azure.com.")]
    [InlineData("comuni_itn_pg.postgres.database.azure.com")]
    public void Hosted_rejects_ip_local_alias_multihost_and_non_azure_fqdn(string host)
    {
        Reject(Valid.Replace("comuni-itn-001-pg.postgres.database.azure.com", host,
            StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("comuniadmin")]
    [InlineData("comuni_platform_reader")]
    [InlineData("postgres")]
    [InlineData("")]
    public void Hosted_rejects_schema_owner_platform_reader_and_missing_runtime_role(string username)
    {
        Reject(Valid.Replace("Username=comuni_app_runtime", "Username=" + username,
            StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Port=5433")]
    [InlineData("Port=0")]
    [InlineData("Database=")]
    [InlineData("Password=")]
    public void Hosted_requires_normal_port_database_and_secret(string replacement)
    {
        var target = replacement.StartsWith("Port=", StringComparison.Ordinal)
            ? "Port=5432"
            : replacement.StartsWith("Database=", StringComparison.Ordinal)
                ? "Database=comuni" : "Password=" + Secret;
        Reject(Valid.Replace(target, replacement, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Testing")]
    [InlineData("Development")]
    public void A_missing_or_blank_connection_is_never_accepted(string environmentName)
    {
        Reject(null, environmentName);
        Reject("", environmentName);
        Reject("  ", environmentName);
    }

    [Fact]
    public void Malformed_connection_is_rejected_without_logging_the_secret()
    {
        Reject(Valid + ";UnknownNpgsqlParameter=" + Secret);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void Local_postgres_without_tls_remains_available_for_synthetic_tests(string environmentName)
    {
        const string local = "Host=localhost;Port=5432;Database=comuni;" +
                             "Username=postgres;Password=synthetic;SSL Mode=Disable";
        Assert.Equal(local, Read(local, environmentName));
    }
}

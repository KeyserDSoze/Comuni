using Comuni.Api.Security;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first: a matching Azure suffix is NOT enough; the SQL credential must
/// be restricted to the exact server FQDN supplied independently by ARM.
/// </summary>
public sealed class RuntimePostgresExpectedHostTests
{
    private const string Host = "comuni-itn-001-pg.postgres.database.azure.com";
    private const string Other = "attacker-pg.postgres.database.azure.com";
    private const string Secret = "synthetic-test-runtime-postgres-password-no-logs";
    private const string Connection =
        "Host=" + Host + ";Port=5432;Database=comuni;Username=comuni_app_runtime;" +
        "Password=" + Secret + ";SSL Mode=VerifyFull;Trust Server Certificate=false";

    private static IConfiguration Config(string? host, string? connection = Connection)
    {
        var values = new Dictionary<string, string?> {
            ["ConnectionStrings:Default"] = connection,
            ["RuntimePostgres:ExpectedHost"] = host
        };
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static void Reject(string? expected, string environment = "Production",
                               string? connection = Connection)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => RuntimePostgresConnectionSettings.Read(Config(expected, connection), environment));
        Assert.DoesNotContain(Secret, error.Message);
        Assert.DoesNotContain(Host, error.Message);
        Assert.DoesNotContain(Other, error.Message);
        Assert.DoesNotContain("Password=", error.Message);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Preview")]
    public void Hosted_accepts_exact_independent_server_identity(string environment)
    {
        Assert.Equal(Connection, RuntimePostgresConnectionSettings.Read(Config(Host), environment));
        Assert.Equal(Connection, RuntimePostgresConnectionSettings.Read(
            Config(Host.ToUpperInvariant()), environment));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("another-pg.postgres.database.azure.com")]
    [InlineData("comuni-itn-001-pg.postgres.database.azure.com.attacker.test")]
    [InlineData("postgres.database.azure.com")]
    [InlineData("localhost")]
    [InlineData("10.90.2.10")]
    [InlineData("comuni-itn-001-pg.postgres.database.azure.com,attacker-pg.postgres.database.azure.com")]
    public void Hosted_rejects_missing_malformed_or_different_expected_host(string? host)
    {
        Reject(host);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void A_different_valid_azure_postgres_server_is_not_trusted(string environment)
    {
        Reject(Host, environment, Connection.Replace(Host, Other, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void Local_postgres_fixture_does_not_require_a_host_metadata_binding(string environment)
    {
        const string local = "Host=localhost;Database=comuni;Username=postgres;Password=synthetic";
        Assert.Equal(local, RuntimePostgresConnectionSettings.Read(Config(null, local), environment));
    }
}

using Comuni.Api.Security;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first tests: a global SQL reader credential must not connect to an
/// unauthenticated server in hosted environments (synthetic strings only).
/// </summary>
public sealed class PlatformInventoryTlsSettingsTests
{
    private const string Default = "Host=pg.comuni.example.test;Port=5432;Database=comuni;" +
        "Username=comuni_app_runtime;Password=synthetic-only-runtime-test-password";
    private const string Reader = "Host=pg.comuni.example.test;Port=5432;Database=comuni;" +
        "Username=comuni_platform_reader;Password=synthetic-only-platform-test-password";

    private static IConfiguration Config(string? reader, string enabled = "true")
    {
        var values = new Dictionary<string, string?>
        {
            ["PlatformInventory:Enabled"] = enabled,
            ["ConnectionStrings:PlatformRead"] = reader
        };
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    [Theory]
    [InlineData("Production", "Disable")]
    [InlineData("Production", "Prefer")]
    [InlineData("Production", "Require")]
    [InlineData("Production", "VerifyCA")]
    [InlineData("Staging", "Require")]
    [InlineData("Staging", "VerifyCA")]
    [InlineData("Preview", "Prefer")]
    public void Hosted_global_reader_denies_tls_without_certificate_and_hostname_verification(
        string environmentName, string mode)
    {
        var password = "synthetic-only-platform-test-password";
        var result = Assert.Throws<InvalidOperationException>(
            () => PlatformInventorySettings.Read(
                Config(Reader + ";SSL Mode=" + mode),
                "Oidc", Default, environmentName));
        Assert.DoesNotContain(password, result.Message);
        Assert.DoesNotContain(Reader, result.Message);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void Hosted_reader_rejects_trust_server_certificate_bypass_even_with_verify_full(
        string environmentName)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => PlatformInventorySettings.Read(Config(
                Reader + ";SSL Mode=VerifyFull;Trust Server Certificate=true"),
                "Oidc", Default, environmentName));
        Assert.DoesNotContain("synthetic-only-platform-test-password", error.Message);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Preview")]
    public void Hosted_reader_with_verified_hostname_and_certificate_is_accepted(
        string environmentName)
    {
        var value = Reader + ";SSL Mode=VerifyFull;Trust Server Certificate=false";
        var settings = PlatformInventorySettings.Read(
            Config(value), "Oidc", Default, environmentName);
        Assert.True(settings.Enabled);
        var parsed = new NpgsqlConnectionStringBuilder(settings.ConnectionString);
        Assert.Equal(SslMode.VerifyFull, parsed.SslMode);
        Assert.False(parsed.TrustServerCertificate);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void Local_reader_keeps_existing_unencrypted_synthetic_postgres_fixture(
        string environmentName)
    {
        var settings = PlatformInventorySettings.Read(
            Config(Reader), "Oidc", Default, environmentName);
        Assert.True(settings.Enabled);
    }

    [Fact]
    public void Disabled_inventory_remains_off_without_a_secret_or_oidc()
    {
        var settings = PlatformInventorySettings.Read(
            Config(null, "false"), "DevelopmentJwt", Default, "Production");
        Assert.False(settings.Enabled);
        Assert.Null(settings.ConnectionString);
    }

    [Theory]
    [InlineData("comuni_app_runtime", "comuni", "pg.comuni.example.test", "Oidc")]
    [InlineData("comuni_platform_reader", "otherdb", "pg.comuni.example.test", "Oidc")]
    [InlineData("comuni_platform_reader", "comuni", "evil.example.test", "Oidc")]
    [InlineData("comuni_platform_reader", "comuni", "pg.comuni.example.test", "DevelopmentJwt")]
    public void Separate_oidc_platform_reader_same_server_and_db_remains_required(
        string user, string database, string host, string authenticationMode)
    {
        var alternate = $"Host={host};Port=5432;Database={database};Username={user};" +
            "Password=synthetic-test-password-only;SSL Mode=VerifyFull;Trust Server Certificate=false";
        Assert.Throws<InvalidOperationException>(() =>
            PlatformInventorySettings.Read(
                Config(alternate), authenticationMode, Default, "Production"));
    }
}

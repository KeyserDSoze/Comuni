using Comuni.Api.Security;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class BrowserOidcSettingsTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            values.ToDictionary(kv => kv.Key, kv => (string?)kv.Value)).Build();

    private static readonly (string, string)[] Valid =
    [
        ("Authentication:Mode", "Oidc"),
        ("Authentication:Authority", "https://identity.example.test/tenant/v2.0"),
        ("Authentication:Audience", "comuni-api"),
        ("Authentication:BrowserClientId", "public-react-client"),
        ("Authentication:BrowserAuthorizationEndpoint", "https://identity.example.test/oauth2/v2.0/authorize"),
        ("Authentication:BrowserTokenEndpoint", "https://identity.example.test/oauth2/v2.0/token"),
        ("Authentication:BrowserScope", "openid profile api://comuni-api/access_as_user")
    ];

    [Fact]
    public void DevelopmentJwt_never_exposes_a_browser_OIDC_client()
    {
        var config = Config(("Authentication:Mode", "DevelopmentJwt"));
        var settings = BrowserOidcSettings.Read(config, "DevelopmentJwt", "Development");
        Assert.Equal("DevelopmentJwt", settings.Mode);
        Assert.False(settings.Enabled);
        Assert.Null(settings.ClientId);
    }

    [Fact]
    public void Oidc_without_browser_settings_fails_closed_with_no_manual_token_mode()
    {
        var settings = BrowserOidcSettings.Read(Config(("Authentication:Authority", "https://identity.example.test/")), "Oidc", "Production");
        Assert.Equal("Oidc", settings.Mode);
        Assert.False(settings.Enabled);
        Assert.Null(settings.TokenEndpoint);
    }

    [Fact]
    public void Secure_browser_provider_configuration_exposes_only_public_client_fields()
    {
        var settings = BrowserOidcSettings.Read(Config(Valid), "Oidc", "Production");
        Assert.True(settings.Enabled);
        Assert.Equal("public-react-client", settings.ClientId);
        Assert.Equal("https://identity.example.test/oauth2/v2.0/token", settings.TokenEndpoint);
        Assert.Equal("https://identity.example.test/tenant/v2.0", settings.Issuer);
        Assert.Contains("openid", settings.Scope!);
    }

    [Theory]
    [InlineData("Authentication:BrowserAuthorizationEndpoint", "http://identity.example.test/authorize")]
    [InlineData("Authentication:BrowserAuthorizationEndpoint", "https://malicious.example.test/authorize")]
    [InlineData("Authentication:BrowserTokenEndpoint", "https://malicious.example.test/token")]
    [InlineData("Authentication:BrowserTokenEndpoint", "https://username:password@identity.example.test/token")]
    [InlineData("Authentication:BrowserTokenEndpoint", "https://identity.example.test/token?foo=bar")]
    [InlineData("Authentication:BrowserScope", "openid profile offline_access api://comuni-api/access_as_user")]
    [InlineData("Authentication:BrowserScope", "profile api://comuni-api/access_as_user")]
    [InlineData("Authentication:BrowserClientId", "")]
    public void Browser_auth_rejects_unsafe_or_incomplete_configuration(string key, string unsafeValue)
    {
        var values = Valid.Select(v => v.Item1 == key ? (v.Item1, unsafeValue) : v).ToArray();
        Assert.Throws<InvalidOperationException>(
            () => BrowserOidcSettings.Read(Config(values), "Oidc", "Production"));
    }

    [Fact]
    public void Production_browser_flow_never_accepts_an_implicit_client_secret()
    {
        var values = Valid.Append(("Authentication:BrowserClientSecret", "should-never-be-in-spa")).ToArray();
        Assert.Throws<InvalidOperationException>(
            () => BrowserOidcSettings.Read(Config(values), "Oidc", "Production"));
    }

    [Fact]
    public void Public_endpoint_is_anonymous_and_disabled_during_demo_mode()
    {
        // In the frontend demo only the local HS256 form is allowed;
        // the OIDC settings must not be mistaken for an identity provider.
        var settings = BrowserOidcSettings.Read(Config(("Authentication:Mode", "DevelopmentJwt")), "DevelopmentJwt", "Testing");
        Assert.False(settings.Enabled);
    }
}

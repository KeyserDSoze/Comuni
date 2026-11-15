using Comuni.Api.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class AuthenticationConfigurationTests
{
    private static IConfiguration Config(params (string Key, string Value)[] pairs) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            pairs.ToDictionary(x => x.Key, x => (string?)x.Value)).Build();

    [Fact]
    public void Production_rejects_demo_HS256_even_if_signing_key_is_valid()
    {
        var config = Config(
            ("Authentication:Mode", "DevelopmentJwt"),
            ("Jwt:SigningKey", ApiFactory.SigningKey),
            ("Jwt:Issuer", "Demo"), ("Jwt:Audience", "Comuni.Api"));
        Assert.Throws<InvalidOperationException>(
            () => AuthenticationConfiguration.Read(config, "Production"));
    }

    [Fact]
    public void Production_requires_explicit_OIDC_authority()
    {
        var config = Config(("Authentication:Audience", "Comuni.Api"));
        Assert.Throws<InvalidOperationException>(
            () => AuthenticationConfiguration.Read(config, "Production"));
    }

    [Theory]
    [InlineData("http://identity.example.test/")]
    [InlineData("not-an-absolute-url")]
    [InlineData("https://user:password@identity.example.test/")]
    public void Oidc_rejects_insecure_authority(string authority)
    {
        var config = Config(("Authentication:Mode", "Oidc"),
            ("Authentication:Authority", authority), ("Authentication:Audience", "Comuni.Api"));
        Assert.Throws<InvalidOperationException>(
            () => AuthenticationConfiguration.Read(config, "Production"));
    }

    [Fact]
    public void Oidc_requires_a_target_audience()
    {
        var config = Config(("Authentication:Mode", "Oidc"),
            ("Authentication:Authority", "https://identity.example.test/"));
        Assert.Throws<InvalidOperationException>(
            () => AuthenticationConfiguration.Read(config, "Production"));
    }

    [Fact]
    public void Production_rejects_leftover_demo_signing_key()
    {
        var config = Config(("Authentication:Mode", "Oidc"),
            ("Authentication:Authority", "https://identity.example.test/"),
            ("Authentication:Audience", "Comuni.Api"), ("Jwt:SigningKey", ApiFactory.SigningKey));
        Assert.Throws<InvalidOperationException>(
            () => AuthenticationConfiguration.Read(config, "Production"));
    }

    [Fact]
    public void Valid_OIDC_configuration_requires_https_and_RSA_signature_validation()
    {
        var config = Config(("Authentication:Mode", "Oidc"),
            ("Authentication:Authority", "https://identity.example.test/"),
            ("Authentication:Audience", "Comuni.Api"));
        var auth = AuthenticationConfiguration.Read(config, "Production");
        var options = new JwtBearerOptions();
        auth.Apply(options);
        Assert.Equal("https://identity.example.test/", options.Authority);
        Assert.Equal("Comuni.Api", options.Audience);
        Assert.True(options.RequireHttpsMetadata);
        Assert.False(options.MapInboundClaims);
        Assert.True(options.TokenValidationParameters.ValidateIssuer);
        Assert.True(options.TokenValidationParameters.ValidateAudience);
        Assert.True(options.TokenValidationParameters.ValidateIssuerSigningKey);
        Assert.True(options.TokenValidationParameters.RequireSignedTokens);
        Assert.True(options.TokenValidationParameters.RequireExpirationTime);
        Assert.Contains("RS256", options.TokenValidationParameters.ValidAlgorithms!);
        Assert.DoesNotContain("HS256", options.TokenValidationParameters.ValidAlgorithms!);
    }

    [Fact]
    public void Demo_mode_is_allowed_only_for_development_and_tests()
    {
        var config = Config(("Authentication:Mode", "DevelopmentJwt"),
            ("Jwt:SigningKey", ApiFactory.SigningKey),
            ("Jwt:Issuer", "Comuni.Tests"), ("Jwt:Audience", "Comuni.Api"));
        var settings = AuthenticationConfiguration.Read(config, "Testing");
        var options = new JwtBearerOptions();
        settings.Apply(options);
        Assert.Contains("HS256", options.TokenValidationParameters.ValidAlgorithms!);
        Assert.Null(options.Authority);
    }
}

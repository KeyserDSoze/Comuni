using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Comuni.Api.Security;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first: signed compact JWTs can contain duplicate JSON property names
/// which an identity parser might silently collapse before ClaimsPrincipal.
/// No real issuer, tenant identity or secret is used.
/// </summary>
public sealed class SignedDuplicateJwtPayloadTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    internal static string Payload(string issuer, string subject, string organization, string audience,
        string extra = "")
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return $$"""{"iss":{{JsonSerializer.Serialize(issuer)}},"aud":{{JsonSerializer.Serialize(audience)}},"sub":{{JsonSerializer.Serialize(subject)}},"organization_id":{{JsonSerializer.Serialize(organization)}},"iat":{{now}},"exp":{{now + 600}}{{extra}}}""";
    }

    internal static string Encode(string source) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(source))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string SignedHs256(string payload)
    {
        var message = Encode("""{"alg":"HS256","typ":"JWT"}""") + "." + Encode(payload);
        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes(ApiFactory.SigningKey));
        var signature = Convert.ToBase64String(mac.ComputeHash(Encoding.ASCII.GetBytes(message)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return message + "." + signature;
    }

    [Theory]
    [InlineData("organization_id", ApiFactory.OrgA)]
    [InlineData("organization_id", ApiFactory.OrgB)]
    [InlineData("sub", "test-reader")]
    [InlineData("sub", "test-admin")]
    [InlineData("iss", "Comuni.Tests")]
    [InlineData("iss", "Comuni.Evil")]
    [InlineData("aud", "Comuni.Api")]
    [InlineData("aud", "Another.Api")]
    [InlineData("role", "Reader")]
    public async Task Signed_duplicate_top_level_JSON_claims_are_unauthorized(
        string name, string value)
    {
        var extra = "," + JsonSerializer.Serialize(name) + ":" + JsonSerializer.Serialize(value);
        // Unlike the identity claims, "role" is not present in the base
        // synthetic payload. Make it a real duplicate instead of testing a
        // legitimate single optional role.
        if (name == "role")
            extra = "," + JsonSerializer.Serialize("role") + ":" +
                    JsonSerializer.Serialize("Reader") + extra;
        var payload = Payload("Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api", extra);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(payload));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Theory]
    [InlineData(""","custom":{"one":1,"one":2}""")]
    [InlineData(""","custom":{"inner":{"key":"a","key":"b"}}""")]
    [InlineData(""","custom":[{"one":1,"one":2}]""")]
    public async Task Signed_nested_duplicate_JSON_keys_are_unauthorized(string extra)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(Payload(
                "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api", extra)));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Unicode_escaped_duplicate_property_name_cannot_bypass_guard()
    {
        // JSON property names are compared after unescaping, so this is a
        // second "sub" even though the original bytes are different.
        var escapedName = JsonSerializer.Serialize("sub").Replace(
            "sub", @"\u0073ub", StringComparison.Ordinal);
        var extra = "," + escapedName + ":" + JsonSerializer.Serialize("test-reader");
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(Payload(
                "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api", extra)));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Overlarge_signed_payload_is_rejected_without_logging_token()
    {
        var extra = "," + JsonSerializer.Serialize("custom") + ":" +
                    JsonSerializer.Serialize(new string('x', 70 * 1024));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(Payload(
                "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api", extra)));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Theory]
    [InlineData(",")]
    [InlineData(""","malformed":/*comment*/1""")]
    public async Task Malformed_but_signed_JSON_cannot_authenticate(string extra)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(Payload(
                "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api", extra)));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Single_valid_signed_payload_retains_municipal_access()
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", SignedHs256(Payload(
                "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api")));
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public void Both_authentication_modes_register_a_post_validation_payload_guard()
    {
        foreach (var environment in new[] { "Testing", "Production" })
        {
            var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Authentication:Mode"] = environment == "Testing" ? "DevelopmentJwt" : "Oidc",
                    ["Jwt:SigningKey"] = environment == "Testing" ? ApiFactory.SigningKey : null,
                    ["Jwt:Issuer"] = "Comuni.Tests",
                    ["Jwt:Audience"] = "Comuni.Api",
                    ["Authentication:Authority"] = "https://issuer.comuni.test/",
                    ["Authentication:Audience"] = "Comuni.Api"
                }).Build();
            var options = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions();
            AuthenticationConfiguration.Read(config, environment).Apply(options);
            Assert.NotNull(options.Events.OnTokenValidated);
        }
    }
}

public sealed class SignedDuplicateOidcJwtPayloadTests(OidcApiFactory factory)
    : IClassFixture<OidcApiFactory>
{
    [Theory]
    [InlineData("organization_id", OidcApiFactory.OrganizationId)]
    [InlineData("organization_id", ApiFactory.OrgB)]
    [InlineData("sub", "oidc-user")]
    [InlineData("iss", OidcApiFactory.Issuer)]
    [InlineData("aud", OidcApiFactory.Audience)]
    public async Task RS256_signed_duplicate_claims_cannot_access_municipality(
        string key, string value)
    {
        var payload = SignedDuplicateJwtPayloadTests.Payload(
            OidcApiFactory.Issuer, "oidc-user", OidcApiFactory.OrganizationId,
            OidcApiFactory.Audience,
            "," + JsonSerializer.Serialize(key) + ":" + JsonSerializer.Serialize(value));
        using var client = factory.Authenticated(factory.RawSignedToken(payload));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Normal_RS256_signed_raw_JWT_still_works_with_mock_JWKS()
    {
        using var client = factory.Authenticated(factory.RawSignedToken(
            SignedDuplicateJwtPayloadTests.Payload(
                OidcApiFactory.Issuer, "oidc-user", OidcApiFactory.OrganizationId,
                OidcApiFactory.Audience)));
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }
}

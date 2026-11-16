using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Comuni.Api.Security;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED: JWS header JSON can be ambiguous even when the signature validates.
/// Always read the cryptographically checked SecurityToken and reject the
/// original duplicate names, never select one alg/kid/typ by parser behavior.
/// </summary>
public sealed class SignedDuplicateJoseHeaderTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string ValidHeader = """{"alg":"HS256","typ":"JWT"}""";

    private static string Signed(string rawHeader)
    {
        var payload = SignedDuplicateJwtPayloadTests.Payload(
            "Comuni.Tests", "test-reader", ApiFactory.OrgA, "Comuni.Api");
        var message = SignedDuplicateJwtPayloadTests.Encode(rawHeader) + "." +
                      SignedDuplicateJwtPayloadTests.Encode(payload);
        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes(ApiFactory.SigningKey));
        var signature = Convert.ToBase64String(mac.ComputeHash(Encoding.ASCII.GetBytes(message)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return message + "." + signature;
    }

    [Theory]
    [InlineData("""{"alg":"HS256","typ":"JWT","alg":"HS256"}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","typ":"JWT"}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","kid":"a","kid":"a"}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","kid":"a","kid":"b"}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","\u0061lg":"HS256"}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","custom":{"a":1,"a":2}}""")]
    [InlineData("""{"alg":"HS256","typ":"JWT","custom":[{"a":1,"a":2}]}""")]
    public async Task Signed_duplicate_JOSE_names_are_rejected_before_municipal_access(
        string rawHeader)
    {
        var compact = Signed(rawHeader);
        // This assertion covers the case where another JWT parser accepts
        // the signature/header and silently drops a duplicate field.
        Assert.False(JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact)));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", compact);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Large_but_signed_header_fails_bounded_guard_without_echoing_JWT()
    {
        var largeHeader = """{"alg":"HS256","typ":"JWT","custom":""" +
                          System.Text.Json.JsonSerializer.Serialize(new string('x', 9 * 1024)) + "}";
        var compact = Signed(largeHeader);
        Assert.False(JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact)));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", compact);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Well_formed_single_header_keeps_valid_dev_signed_JWT()
    {
        var compact = Signed(ValidHeader);
        Assert.True(JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact)));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", compact);
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }
}

public sealed class SignedDuplicateOidcJoseHeaderTests(OidcApiFactory factory)
    : IClassFixture<OidcApiFactory>
{
    private const string PayloadIssuer = OidcApiFactory.Issuer;
    private const string KeyId = "test-oidc-rsa-key";

    [Theory]
    [InlineData("""{"alg":"RS256","typ":"JWT","kid":"test-oidc-rsa-key","kid":"test-oidc-rsa-key"}""")]
    [InlineData("""{"alg":"RS256","typ":"JWT","kid":"test-oidc-rsa-key","alg":"RS256"}""")]
    [InlineData("""{"alg":"RS256","typ":"JWT","kid":"test-oidc-rsa-key","typ":"JWT"}""")]
    [InlineData("""{"alg":"RS256","typ":"JWT","kid":"test-oidc-rsa-key","custom":{"x":1,"x":2}}""")]
    public async Task RS256_signed_duplicate_JOSE_header_is_unauthorized(string header)
    {
        var compact = factory.RawSignedToken(
            SignedDuplicateJwtPayloadTests.Payload(
                PayloadIssuer, "oidc-user", OidcApiFactory.OrganizationId,
                OidcApiFactory.Audience), header);
        Assert.False(JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact)));
        using var client = factory.Authenticated(compact);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Single_JOSE_header_preserves_real_RS256_verification_with_fake_JWKS()
    {
        var compact = factory.RawSignedToken(
            SignedDuplicateJwtPayloadTests.Payload(
                PayloadIssuer, "oidc-user", OidcApiFactory.OrganizationId,
                OidcApiFactory.Audience));
        Assert.True(JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact)));
        using var client = factory.Authenticated(compact);
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }
}

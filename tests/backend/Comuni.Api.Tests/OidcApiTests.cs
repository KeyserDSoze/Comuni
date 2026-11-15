using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Local OIDC discovery/JWKS configuration; no external network or production identity provider.
/// </summary>
public sealed class OidcApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public const string Issuer = "https://issuer.comuni.test/";
    public const string Audience = "Comuni.Api";
    public const string OrganizationId = "dddddddd-dddd-dddd-dddd-dddddddddddd";
    private readonly RSA _rsa = RSA.Create(2048);
    private const string KeyId = "test-oidc-rsa-key";

    public OidcApiFactory()
    {
        var connection = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION required.");
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", connection);
        Environment.SetEnvironmentVariable("Authentication__Mode", "Oidc");
        Environment.SetEnvironmentVariable("Authentication__Authority", Issuer);
        Environment.SetEnvironmentVariable("Authentication__Audience", Audience);
        Environment.SetEnvironmentVariable("Jwt__SigningKey", null);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) =>
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Mode"] = "Oidc",
                ["Authentication:Authority"] = Issuer,
                ["Authentication:Audience"] = Audience
            }));
        builder.ConfigureTestServices(services =>
            services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
                    metadata.SigningKeys.Add(new RsaSecurityKey(_rsa.ExportParameters(false)) { KeyId = KeyId });
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
                }));
    }

    public async Task InitializeAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO platform.organizations (id, name) VALUES
              ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'OIDC Test Municipality')
            ON CONFLICT (id) DO NOTHING;
            INSERT INTO platform.organization_memberships
                (organization_id, subject, role, is_active, identity_issuer) VALUES
              ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'oidc-user', 'Reader', TRUE, 'https://issuer.comuni.test/'),
              ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'oidc-admin', 'Admin', TRUE, 'https://issuer.comuni.test/'),
              ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'oidc-legacy', 'Reader', TRUE, NULL),
              ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'oidc-foreign', 'Reader', TRUE, 'https://other-issuer.example.test/')
            ON CONFLICT (organization_id, subject, role)
                DO UPDATE SET is_active = TRUE, identity_issuer = EXCLUDED.identity_issuer;
            """);
    }

    public new Task DisposeAsync()
    {
        base.Dispose();
        _rsa.Dispose();
        Environment.SetEnvironmentVariable("Authentication__Mode", null);
        Environment.SetEnvironmentVariable("Authentication__Authority", null);
        Environment.SetEnvironmentVariable("Authentication__Audience", null);
        return Task.CompletedTask;
    }

    internal string Token(string issuer = Issuer, string audience = Audience,
        string subject = "oidc-user", string organizationId = OrganizationId,
        bool symmetric = false, bool expired = false)
    {
        SigningCredentials credentials = symmetric
            ? new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ApiFactory.SigningKey)),
                SecurityAlgorithms.HmacSha256)
            : new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId },
                SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: issuer, audience: audience,
            claims:
            [
                new Claim("sub", subject),
                new Claim("organization_id", organizationId)
            ],
            notBefore: expired ? DateTime.UtcNow.AddHours(-2) : DateTime.UtcNow.AddMinutes(-1),
            expires: expired ? DateTime.UtcNow.AddHours(-1) : DateTime.UtcNow.AddMinutes(10),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    internal HttpClient Authenticated(string token)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }
}

public sealed class OidcApiTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    [Fact]
    public async Task Trusted_RS256_token_with_active_membership_can_access_its_context()
    {
        using var client = factory.Authenticated(factory.Token());
        var response = await client.GetAsync("/api/v1/context");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var text = await response.Content.ReadAsStringAsync();
        Assert.Contains("OIDC Test Municipality", text);
        Assert.Contains("Reader", text);
    }

    [Fact]
    public async Task RS256_with_wrong_issuer_is_unauthorized()
    {
        using var client = factory.Authenticated(factory.Token(issuer: "https://evil.example.test/"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task RS256_with_wrong_audience_is_unauthorized()
    {
        using var client = factory.Authenticated(factory.Token(audience: "Other.Api"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task HS256_demo_token_is_never_accepted_in_OIDC_mode()
    {
        using var client = factory.Authenticated(factory.Token(symmetric: true));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Expired_RS256_token_is_unauthorized()
    {
        using var client = factory.Authenticated(factory.Token(expired: true));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task RS256_user_without_membership_is_forbidden()
    {
        using var client = factory.Authenticated(factory.Token(subject: "unassigned-oidc-user"));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Theory]
    [InlineData("oidc-legacy")]
    [InlineData("oidc-foreign")]
    public async Task Valid_oidc_JWT_must_not_authorize_unbound_or_other_issuer_membership(string subject)
    {
        using var client = factory.Authenticated(factory.Token(subject: subject));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Trusted_issuer_admin_provisions_new_member_with_issuer_from_validated_JWT()
    {
        var subject = "oidc-assignee-" + Guid.NewGuid().ToString("N");
        using var admin = factory.Authenticated(factory.Token(subject: "oidc-admin"));
        var response = await admin.PutAsJsonAsync("/api/v1/admin/memberships/Reader", new
        {
            subject, enabled = true,
            identityIssuer = "https://evil-issuer.example.test/",
            issuer = "https://evil-issuer.example.test/"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var result = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(OidcApiFactory.Issuer, result.RootElement.GetProperty("issuer").GetString());
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var row = await db.OrganizationMemberships.IgnoreQueryFilters().AsNoTracking()
            .SingleAsync(x => x.OrganizationId == Guid.Parse(OidcApiFactory.OrganizationId) &&
                x.Subject == subject && x.Role == "Reader");
        Assert.Equal(OidcApiFactory.Issuer, row.IdentityIssuer);
        Assert.True(row.IsActive);
        using var reader = factory.Authenticated(factory.Token(subject: subject));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Oidc_admin_cannot_silently_rebind_legacy_or_foreign_issuer_membership()
    {
        using var admin = factory.Authenticated(factory.Token(subject: "oidc-admin"));
        foreach (var subject in new[] { "oidc-legacy", "oidc-foreign" })
        {
            Assert.Equal(HttpStatusCode.Conflict,
                (await admin.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                    new { subject, enabled = true })).StatusCode);
        }
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var rows = await db.OrganizationMemberships.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.OrganizationId == Guid.Parse(OidcApiFactory.OrganizationId) &&
                (x.Subject == "oidc-legacy" || x.Subject == "oidc-foreign"))
            .ToDictionaryAsync(x => x.Subject);
        Assert.Null(rows["oidc-legacy"].IdentityIssuer);
        Assert.Equal("https://other-issuer.example.test/", rows["oidc-foreign"].IdentityIssuer);
    }

    [Fact]
    public async Task Concurrent_OIDC_Reader_grants_are_idempotent_and_audited_only_once()
    {
        var subject = "oidc-concurrent-" + Guid.NewGuid().ToString("N");
        using var first = factory.Authenticated(factory.Token(subject: "oidc-admin"));
        using var second = factory.Authenticated(factory.Token(subject: "oidc-admin"));
        var path = "/api/v1/admin/memberships/Reader";
        var responses = await Task.WhenAll(
            first.PutAsJsonAsync(path, new { subject, enabled = true }),
            second.PutAsJsonAsync(path, new { subject, enabled = true }));
        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));

        var org = Guid.Parse(OidcApiFactory.OrganizationId);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{org:D}|Reader|{subject}|{OidcApiFactory.Issuer}"));
        var resourceId = new Guid(digest.AsSpan(0, 16));
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var audits = await db.AuditEvents.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.OrganizationId == org &&
                x.ResourceId == resourceId &&
                x.Action == "platform.membership.reader.activated")
            .ToArrayAsync();
        var audit = Assert.Single(audits);
        Assert.Equal("oidc-admin", audit.ActorSubject);
        Assert.Equal("platform.membership", audit.ResourceType);
        Assert.Equal(1, await db.OrganizationMemberships.IgnoreQueryFilters().CountAsync(
            x => x.OrganizationId == org && x.Subject == subject &&
                x.Role == "Reader" && x.IdentityIssuer == OidcApiFactory.Issuer && x.IsActive));
    }

    [Fact]
    public async Task RS256_user_with_Reader_membership_cannot_write()
    {
        using var client = factory.Authenticated(factory.Token());
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/api/v1/protocol/records", new { subject = "Non consentito" })).StatusCode);
    }
}

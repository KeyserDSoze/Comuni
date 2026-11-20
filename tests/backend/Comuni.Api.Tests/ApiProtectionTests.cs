using System.Net;
using System.Security.Claims;
using Comuni.Api.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class ApiProtectionConfigurationTests
{
    [Theory]
    [InlineData("0", "60")]
    [InlineData("-1", "60")]
    [InlineData("10001", "60")]
    [InlineData("garbage", "60")]
    [InlineData("10", "0")]
    [InlineData("10", "3601")]
    [InlineData("10", "not-a-number")]
    public void Invalid_rate_limit_settings_fail_at_startup(string permits, string window)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Security:ApiRateLimit:PermitLimit"] = permits,
                ["Security:ApiRateLimit:WindowSeconds"] = window
            }).Build();
        Assert.Throws<InvalidOperationException>(() => ApiProtectionSettings.Read(config));
    }

    [Fact]
    public void Unknown_forwarded_for_header_never_changes_anonymous_partition()
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        var first = ApiProtectionSettings.PartitionKey(http);
        http.Request.Headers["X-Forwarded-For"] = "203.0.113.4";
        Assert.Equal(first, ApiProtectionSettings.PartitionKey(http));
        Assert.Equal("ip:198.51.100.12", first);
    }

    [Fact]
    public void Incomplete_authenticated_identity_without_issuer_uses_peer_partition()
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "officer-1"),
            new Claim("organization_id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        ], "verified-token"));
        Assert.Equal("ip:198.51.100.12", ApiProtectionSettings.PartitionKey(http));
    }

    [Fact]
    public void Validated_identity_partitions_by_tenant_and_subject_not_untrusted_header()
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "officer-1"),
            new Claim("iss", "Comuni.Tests"),
            new Claim("organization_id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        ], "verified-token"));
        var first = ApiProtectionSettings.PartitionKey(http);
        http.Request.Headers["X-Forwarded-For"] = "203.0.113.99";
        Assert.Equal(first, ApiProtectionSettings.PartitionKey(http));
        Assert.NotEqual("ip:198.51.100.12", first);

        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "officer-1"),
            new Claim("iss", "Comuni.Tests"),
            new Claim("organization_id", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        ], "verified-token"));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(http));
    }

    private static DefaultHttpContext Identity(string? issuer, string? subject,
        string? organization = null, bool includeOrganization = true,
        params Claim[] extra)
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        var claims = new List<Claim>();
        if (issuer is not null) claims.Add(new Claim("iss", issuer));
        if (subject is not null) claims.Add(new Claim("sub", subject));
        if (includeOrganization && organization is not null)
            claims.Add(new Claim("organization_id", organization));
        claims.AddRange(extra);
        http.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "verified-token"));
        return http;
    }

    [Fact]
    public void Same_tenant_and_subject_from_two_issuers_get_independent_quotas()
    {
        const string org = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        const string subject = "personal-id-127-synthetic";
        var a = Identity("https://issuer-a.example.test/", subject, org);
        var b = Identity("https://issuer-b.example.test/", subject, org);
        var first = ApiProtectionSettings.PartitionKey(a);
        var second = ApiProtectionSettings.PartitionKey(b);
        Assert.NotEqual(first, second);
        Assert.StartsWith("tenant:", first);
        Assert.StartsWith("tenant:", second);
        Assert.Matches("^tenant:[0-9a-f]{64}$", first);
        Assert.DoesNotContain(subject, first);
        Assert.DoesNotContain("issuer-a", first);
        Assert.DoesNotContain(org, first);

        a.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.70");
        a.Request.Headers["X-Forwarded-For"] = "203.0.113.8";
        Assert.Equal(first, ApiProtectionSettings.PartitionKey(a));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(
            Identity("https://issuer-a.example.test/", subject,
                     "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")));
    }

    [Fact]
    public void Authenticated_tenantless_platform_operator_has_separate_quota_from_ip_and_other_operators()
    {
        const string issuer = "https://platform-idp.example.test/";
        const string subject = "platform-operator-127-synthetic";
        var operatorContext = Identity(issuer, subject, includeOrganization: false);
        var first = ApiProtectionSettings.PartitionKey(operatorContext);
        Assert.StartsWith("platform:", first);
        Assert.Matches("^platform:[0-9a-f]{64}$", first);
        Assert.NotEqual("ip:198.51.100.12", first);
        Assert.DoesNotContain(subject, first);
        Assert.DoesNotContain(issuer, first);
        Assert.Equal(first, ApiProtectionSettings.PartitionKey(
            Identity(issuer, subject, includeOrganization: false)));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(
            Identity(issuer, "other-operator", includeOrganization: false)));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(
            Identity("https://other-idp.example.test/", subject,
                     includeOrganization: false)));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(
            Identity(issuer, subject,
                     "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")));

        var anonymous = new DefaultHttpContext();
        anonymous.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        Assert.Equal("ip:198.51.100.12", ApiProtectionSettings.PartitionKey(anonymous));
    }

    [Fact]
    public void Ambiguous_or_unverified_claims_can_never_select_an_authenticated_quota()
    {
        const string issuer = "https://platform-idp.example.test/";
        const string org = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        var invalid = new[]
        {
            Identity(issuer, "subject", org, extra: new Claim("iss", issuer)),
            Identity(issuer, "subject", org, extra: new Claim("sub", "subject")),
            Identity(issuer, "subject", org, extra: new Claim("organization_id", org)),
            Identity(issuer, "subject", "not-a-guid"),
            Identity(issuer, "subject", "00000000-0000-0000-0000-000000000000"),
            Identity(issuer, "subject", includeOrganization: false,
                     extra: new Claim("iss", issuer)),
            Identity(issuer, "subject", organization: "", includeOrganization: false,
                     extra: new Claim("organization_id", "")),
            Identity(null, "subject", includeOrganization: false,
                     extra: new Claim("role", "Superadmin")),
            Identity(issuer, null, includeOrganization: false,
                     extra: new Claim("role", "Superadmin")),
        };
        foreach (var candidate in invalid)
        {
            Assert.Equal("ip:198.51.100.12",
                ApiProtectionSettings.PartitionKey(candidate));
            candidate.Request.Headers["X-Forwarded-For"] = "203.0.113.99";
            Assert.Equal("ip:198.51.100.12",
                ApiProtectionSettings.PartitionKey(candidate));
        }
    }

    [Fact]
    public void Delimiter_shaped_issuer_and_subject_pairs_remain_collision_free()
    {
        const string org = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        var a = Identity("https://idp.example.test/a:b", "c", org);
        var b = Identity("https://idp.example.test/a", "b:c", org);
        Assert.NotEqual(ApiProtectionSettings.PartitionKey(a),
                        ApiProtectionSettings.PartitionKey(b));
    }
}

public sealed class ApiProtectionFactory : WebApplicationFactory<Program>
{
    public ApiProtectionFactory()
    {
        Environment.SetEnvironmentVariable("Authentication__Mode", "DevelopmentJwt");
        Environment.SetEnvironmentVariable("Jwt__SigningKey", ApiFactory.SigningKey);
        Environment.SetEnvironmentVariable("Jwt__Issuer", "Comuni.Tests");
        Environment.SetEnvironmentVariable("Jwt__Audience", "Comuni.Api");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) =>
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
                    ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION is required."),
                ["Authentication:Mode"] = "DevelopmentJwt",
                ["Jwt:SigningKey"] = ApiFactory.SigningKey,
                ["Jwt:Issuer"] = "Comuni.Tests",
                ["Jwt:Audience"] = "Comuni.Api",
                ["Security:ApiRateLimit:PermitLimit"] = "3",
                ["Security:ApiRateLimit:WindowSeconds"] = "60"
            }));
    }
}

/// <summary>
/// Minimal-hosting reads configuration before WebApplicationFactory's config callbacks.
/// The test-only override must be scoped and restored so unrelated tests keep their limits.
/// xUnit parallelization is disabled for the API integration assembly.
/// </summary>
internal sealed class ScopedApiLimit : IDisposable
{
    private const string PermitName = "Security__ApiRateLimit__PermitLimit";
    private const string WindowName = "Security__ApiRateLimit__WindowSeconds";
    private const string ConnectionName = "ConnectionStrings__Default";
    private readonly string? _priorPermit = Environment.GetEnvironmentVariable(PermitName);
    private readonly string? _priorWindow = Environment.GetEnvironmentVariable(WindowName);
    private readonly string? _priorConnection = Environment.GetEnvironmentVariable(ConnectionName);

    public ScopedApiLimit()
    {
        // Minimal hosting evaluates configuration before ConfigureAppConfiguration runs.
        // Do not rely on another test factory having initialized this process-wide setting.
        Environment.SetEnvironmentVariable(ConnectionName,
            Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION is required."));
        Environment.SetEnvironmentVariable(PermitName, "3");
        Environment.SetEnvironmentVariable(WindowName, "60");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(PermitName, _priorPermit);
        Environment.SetEnvironmentVariable(WindowName, _priorWindow);
        Environment.SetEnvironmentVariable(ConnectionName, _priorConnection);
    }
}

public sealed class ApiProtectionIntegrationTests
{
    [Fact]
    public async Task Anonymous_api_requests_are_throttled_and_return_retry_after()
    {
        using var limiter = new ScopedApiLimit();
        using var factory = new ApiProtectionFactory();
        using var client = factory.CreateClient();
        for (var i = 0; i < 3; i++)
        {
            using var response = await client.GetAsync("/api/v1/context");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        using var throttled = await client.GetAsync("/api/v1/context");
        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);
        Assert.True(throttled.Headers.TryGetValues("Retry-After", out var retry));
        Assert.True(int.TryParse(Assert.Single(retry!), out var seconds) && seconds > 0);
        Assert.Equal("no-store", throttled.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Spoofing_forwarded_for_does_not_bypass_quota()
    {
        using var limiter = new ScopedApiLimit();
        using var factory = new ApiProtectionFactory();
        using var client = factory.CreateClient();
        for (var i = 0; i < 3; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/context");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"203.0.113.{i + 1}");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        using var spoofed = new HttpRequestMessage(HttpMethod.Get, "/api/v1/context");
        spoofed.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.100");
        using var rejected = await client.SendAsync(spoofed);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
    }

    [Fact]
    public async Task Health_is_not_rate_limited_and_security_headers_apply_to_all_responses()
    {
        using var limiter = new ScopedApiLimit();
        using var factory = new ApiProtectionFactory();
        using var client = factory.CreateClient();
        for (var i = 0; i < 6; i++)
        {
            using var response = await client.GetAsync("/health/live");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
            Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
            Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
            Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Contains("worker-src 'self'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.False(response.Headers.CacheControl?.NoStore ?? false);
        }
        using var unauthorized = await client.GetAsync("/api/v1/context");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        Assert.Equal("no-store", unauthorized.Headers.CacheControl?.ToString());
        Assert.Equal("nosniff", unauthorized.Headers.GetValues("X-Content-Type-Options").Single());
    }
}

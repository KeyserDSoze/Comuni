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
    public void Validated_identity_partitions_by_tenant_and_subject_not_untrusted_header()
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.12");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "officer-1"),
            new Claim("organization_id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        ], "verified-token"));
        var first = ApiProtectionSettings.PartitionKey(http);
        http.Request.Headers["X-Forwarded-For"] = "203.0.113.99";
        Assert.Equal(first, ApiProtectionSettings.PartitionKey(http));
        Assert.NotEqual("ip:198.51.100.12", first);

        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "officer-1"),
            new Claim("organization_id", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        ], "verified-token"));
        Assert.NotEqual(first, ApiProtectionSettings.PartitionKey(http));
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

public sealed class ApiProtectionIntegrationTests
{
    [Fact]
    public async Task Anonymous_api_requests_are_throttled_and_return_retry_after()
    {
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

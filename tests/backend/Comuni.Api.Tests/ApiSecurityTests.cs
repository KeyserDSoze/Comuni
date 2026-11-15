using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class ApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    internal const string SigningKey = "test-only-key-at-least-thirty-two-characters-long";
    internal const string OrgA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    internal const string OrgB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    internal const string OrgDisabled = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var connection = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION must point to a disposable PostgreSQL test database.");
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = connection,
                ["Jwt:SigningKey"] = SigningKey,
                ["Jwt:Issuer"] = "Comuni.Tests",
                ["Jwt:Audience"] = "Comuni.Api"
            }));
    }

    public async Task InitializeAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.MigrateAsync();

        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO platform.organizations (id, name) VALUES
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Comune A'),
              ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Comune B'),
              ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'Comune senza modulo')
            ON CONFLICT (id) DO NOTHING;
            INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'protocol', TRUE),
              ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'protocol', TRUE),
              ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'protocol', FALSE)
            ON CONFLICT (organization_id, module_key) DO UPDATE SET enabled = EXCLUDED.enabled;
            """);
    }

    public new Task DisposeAsync()
    {
        base.Dispose();
        return Task.CompletedTask;
    }

    internal HttpClient ClientFor(string organization, string role)
    {
        var client = CreateClient();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = Base64Url(JsonSerializer.Serialize(new { alg = "HS256", typ = "JWT" }));
        var payload = Base64Url(JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iss"] = "Comuni.Tests", ["aud"] = "Comuni.Api",
            ["sub"] = "integration-test", ["iat"] = now, ["exp"] = now + 3600,
            ["organization_id"] = organization, ["role"] = role
        }));
        var data = $"{header}.{payload}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SigningKey));
        var signature = Base64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", $"{data}.{signature}");
        return client;
    }

    private static string Base64Url(string value) => Base64Url(Encoding.UTF8.GetBytes(value));
    private static string Base64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public sealed class ApiSecurityTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Anonymous_cannot_read_context()
    {
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Reader_cannot_register_documents()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Reader");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/api/v1/protocol/records", new { subject = "Non consentito" })).StatusCode);
    }

    [Fact]
    public async Task Feature_flag_denies_access_to_disabled_tenant()
    {
        using var client = factory.ClientFor(ApiFactory.OrgDisabled, "Admin");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
    }

    [Fact]
    public async Task Data_created_by_one_organization_cannot_be_read_by_another()
    {
        using var a = factory.ClientFor(ApiFactory.OrgA, "Officer");
        using var b = factory.ClientFor(ApiFactory.OrgB, "Officer");
        var subject = $"Riservato-{Guid.NewGuid():N}";

        var create = await a.PostAsJsonAsync("/api/v1/protocol/records", new { subject });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);

        var aRecords = await a.GetStringAsync("/api/v1/protocol/records");
        var bRecords = await b.GetStringAsync("/api/v1/protocol/records");
        Assert.Contains(subject, aRecords);
        Assert.DoesNotContain(subject, bRecords);
    }

    [Fact]
    public async Task Context_shows_only_enabled_modules_for_current_tenant()
    {
        using var a = factory.ClientFor(ApiFactory.OrgA, "Reader");
        using var disabled = factory.ClientFor(ApiFactory.OrgDisabled, "Reader");
        using var contextA = JsonDocument.Parse(await a.GetStringAsync("/api/v1/context"));
        using var contextDisabled = JsonDocument.Parse(await disabled.GetStringAsync("/api/v1/context"));

        Assert.Contains(contextA.RootElement.GetProperty("modules").EnumerateArray(),
            x => x.GetString() == "protocol");
        Assert.Empty(contextDisabled.RootElement.GetProperty("modules").EnumerateArray());
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Npgsql;
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

    public ApiFactory()
    {
        // Minimal hosting reads configuration before ConfigureWebHost's callbacks.
        // Set test-only environment variables before the Program entry point executes.
        var connection = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION must be set.");
        Environment.SetEnvironmentVariable("ConnectionStrings__Default", connection);
        Environment.SetEnvironmentVariable("Authentication__Mode", "DevelopmentJwt");
        Environment.SetEnvironmentVariable("Jwt__SigningKey", SigningKey);
        Environment.SetEnvironmentVariable("Jwt__Issuer", "Comuni.Tests");
        Environment.SetEnvironmentVariable("Jwt__Audience", "Comuni.Api");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var connection = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION must point to a disposable PostgreSQL test database.");
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = connection,
                ["Authentication:Mode"] = "DevelopmentJwt",
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
            INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','test-admin','Admin',TRUE),
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','test-officer','Officer',TRUE),
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','test-reader','Reader',TRUE),
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','only-a','Officer',TRUE),
              ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','inactive-user','Admin',FALSE),
              ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','test-admin','Admin',TRUE),
              ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','test-officer','Officer',TRUE),
              ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','test-reader','Reader',TRUE),
              ('cccccccc-cccc-cccc-cccc-cccccccccccc','test-admin','Admin',TRUE),
              ('cccccccc-cccc-cccc-cccc-cccccccccccc','test-reader','Reader',TRUE)
            ON CONFLICT (organization_id, subject, role) DO UPDATE SET is_active = EXCLUDED.is_active;
            """);
    }

    public new Task DisposeAsync()
    {
        base.Dispose();
        return Task.CompletedTask;
    }

    internal HttpClient ClientFor(string organization, string role, string? subject = null)
    {
        var client = CreateClient();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = Base64Url(JsonSerializer.Serialize(new { alg = "HS256", typ = "JWT" }));
        var payload = Base64Url(JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iss"] = "Comuni.Tests", ["aud"] = "Comuni.Api",
            ["sub"] = subject ?? $"test-{role.ToLowerInvariant()}", ["iat"] = now, ["exp"] = now + 3600,
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
    [Fact]
    public async Task Forged_Admin_JWT_cannot_upgrade_a_Reader_membership()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Admin", "test-reader");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsJsonAsync("/api/v1/protocol/records", new { subject = "Elevazione negata" })).StatusCode);
    }

    [Fact]
    public async Task Context_roles_come_from_database_not_JWT()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Admin", "test-reader");
        using var document = JsonDocument.Parse(await client.GetStringAsync("/api/v1/context"));
        var roles = document.RootElement.GetProperty("roles").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Equal(new[] { "Reader" }, roles);
    }

    [Fact]
    public async Task JWT_for_unassigned_user_is_forbidden()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Admin", "unassigned");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Disabled_membership_is_forbidden_even_with_valid_JWT()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Admin", "inactive-user");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task User_assigned_only_to_A_cannot_enter_B()
    {
        using var client = factory.ClientFor(ApiFactory.OrgB, "Officer", "only-a");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
    }

    [Fact]
    public async Task Officer_membership_writes_despite_nonprivileged_JWT_role_claim()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Reader", "test-officer");
        var response = await client.PostAsJsonAsync("/api/v1/protocol/records", new { subject = $"Officer-{Guid.NewGuid():N}" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Protocol_registration_writes_a_single_minimal_audit_entry()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Officer");
        client.DefaultRequestHeaders.Add("X-Actor-Subject", "forged-admin");
        var subject = $"SENSITIVE-{Guid.NewGuid():N}";
        var response = await client.PostAsJsonAsync("/api/v1/protocol/records",
            new { subject, actorSubject = "forged-admin", correlationId = "forged" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var recordId = document.RootElement.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var audit = await db.AuditEvents.IgnoreQueryFilters()
            .SingleAsync(x => x.ResourceId == recordId);
        Assert.Equal(Guid.Parse(ApiFactory.OrgA), audit.OrganizationId);
        Assert.Equal("test-officer", audit.ActorSubject);
        Assert.Equal("protocol.record.created", audit.Action);
        Assert.Equal("protocol.record", audit.ResourceType);
        Assert.False(string.IsNullOrWhiteSpace(audit.CorrelationId));
        Assert.NotEqual("forged", audit.CorrelationId);
        Assert.DoesNotContain(subject, JsonSerializer.Serialize(audit));
    }

    [Fact]
    public async Task Audit_history_rejects_sql_update_and_delete()
    {
        using var client = factory.ClientFor(ApiFactory.OrgA, "Officer");
        var response = await client.PostAsJsonAsync("/api/v1/protocol/records",
            new { subject = $"Guard-{Guid.NewGuid():N}" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var recordId = document.RootElement.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var audit = await db.AuditEvents.IgnoreQueryFilters()
            .SingleAsync(x => x.ResourceId == recordId);
        await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlInterpolatedAsync($"UPDATE platform.audit_events SET action = {"forged"} WHERE id = {audit.Id}"));
        await Assert.ThrowsAsync<PostgresException>(() =>
            db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM platform.audit_events WHERE id = {audit.Id}"));
    }

}

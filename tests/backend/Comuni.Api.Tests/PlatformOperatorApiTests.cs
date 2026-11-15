using System.Net;
using System.Net.Http.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// TDD: platform operators are OIDC-only and have NO implicit access to any municipality.
/// All operator identities are synthetic and provisioned with the disposable DB owner.
/// </summary>
public sealed class PlatformOperatorApiTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private const string Endpoint = "/api/v1/platform/session";

    private static async Task SeedAsync(OidcApiFactory factory, string issuer, string subject, bool enabled)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO platform.platform_operators(identity_issuer, subject, is_active)
            VALUES ({issuer}, {subject}, {enabled})
            ON CONFLICT (identity_issuer, subject) DO UPDATE SET is_active = EXCLUDED.is_active
            """);
    }

    [Fact]
    public async Task Anonymous_and_unregistered_OIDC_are_denied_without_platform_data()
    {
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync(Endpoint)).StatusCode);
        using var unregistered = factory.Authenticated(factory.Token(
            subject: "unassigned-platform-user", organizationId: ""));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await unregistered.GetAsync(Endpoint)).StatusCode);
        using var forged = factory.Authenticated(factory.Token(
            subject: "never-platform-operator", organizationId: "", assertedRole: "Superadmin"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await forged.GetAsync(Endpoint)).StatusCode);
    }

    [Fact]
    public async Task Municipality_Admin_and_municipal_role_claim_never_grant_platform_access()
    {
        using var municipalAdmin = factory.Authenticated(factory.Token(subject: "oidc-admin"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await municipalAdmin.GetAsync(Endpoint)).StatusCode);
        using var municipalForged = factory.Authenticated(factory.Token(
            subject: "oidc-admin", assertedRole: "Superadmin"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await municipalForged.GetAsync(Endpoint)).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await municipalAdmin.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Active_exact_issuer_sub_without_tenant_claim_gets_only_own_readonly_platform_session()
    {
        var subject = "operator-" + Guid.NewGuid().ToString("N");
        await SeedAsync(factory, OidcApiFactory.Issuer, subject, true);
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        using var response = await client.GetAsync(Endpoint);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var data = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal("Superadmin", data.GetProperty("role").GetString());
        Assert.Equal(1, data.EnumerateObject().Count());
        Assert.DoesNotContain(subject, data.ToString());
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
        using var withTenant = factory.Authenticated(factory.Token(subject: subject));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await withTenant.GetAsync(Endpoint)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await withTenant.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.PutAsJsonAsync(Endpoint, new { role = "Superadmin" })).StatusCode);
    }

    [Fact]
    public async Task Platform_operator_revocation_and_wrong_identity_issuer_fail_closed()
    {
        var subject = "revoked-" + Guid.NewGuid().ToString("N");
        await SeedAsync(factory, OidcApiFactory.Issuer, subject, true);
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(Endpoint)).StatusCode);
        await SeedAsync(factory, OidcApiFactory.Issuer, subject, false);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(Endpoint)).StatusCode);
        var wrongIssuerSubject = "wrong-issuer-" + Guid.NewGuid().ToString("N");
        await SeedAsync(factory, "https://untrusted.example.test/", wrongIssuerSubject, true);
        using var trustedToken = factory.Authenticated(factory.Token(
            subject: wrongIssuerSubject, organizationId: ""));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await trustedToken.GetAsync(Endpoint)).StatusCode);
        using var wrongIssuerToken = factory.Authenticated(factory.Token(
            issuer: "https://untrusted.example.test/", subject: wrongIssuerSubject, organizationId: ""));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await wrongIssuerToken.GetAsync(Endpoint)).StatusCode);
    }

    [Fact]
    public async Task Demo_JWT_cannot_access_platform_endpoint_even_with_superadmin_role_claim()
    {
        await using var demo = new ApiFactory();
        await demo.InitializeAsync();
        using var token = demo.ClientFor(ApiFactory.OrgA, "Superadmin", "test-admin");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await token.GetAsync(Endpoint)).StatusCode);
    }

    [Fact]
    public async Task Runtime_login_has_boolean_check_only_not_operator_roster_access()
    {
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Runtime PostgreSQL login is required.");
        await using var db = new NpgsqlConnection(runtime);
        await db.OpenAsync();
        await using var check = new NpgsqlCommand("""
            SELECT
              has_function_privilege(current_user,
                'platform.is_active_platform_operator(text,text)', 'EXECUTE'),
              has_table_privilege(current_user, 'platform.platform_operators', 'SELECT'),
              has_any_column_privilege(current_user, 'platform.platform_operators', 'INSERT'),
              has_any_column_privilege(current_user, 'platform.platform_operators', 'UPDATE'),
              has_table_privilege(current_user, 'platform.platform_operators', 'DELETE')
            """, db);
        await using var row = await check.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.True(row.GetBoolean(0));
        for (var i = 1; i <= 4; i++) Assert.False(row.GetBoolean(i));
        await row.DisposeAsync();
        await using var count = new NpgsqlCommand(
            "SELECT count(*) FROM platform.platform_operators", db);
        var denied = await Assert.ThrowsAsync<PostgresException>(
            () => count.ExecuteScalarAsync());
        Assert.Equal("42501", denied.SqlState);
        await using var caller = new NpgsqlCommand(
            "SELECT platform.is_active_platform_operator(@issuer, @subject)", db);
        caller.Parameters.AddWithValue("issuer", OidcApiFactory.Issuer);
        caller.Parameters.AddWithValue("subject", "unassigned-platform-user");
        Assert.False((bool)(await caller.ExecuteScalarAsync())!);
    }
}

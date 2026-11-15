using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Security contract for the first global municipality inventory, with a
/// separate SQL login on the SAME PostgreSQL 17 test database.
/// </summary>
public sealed class PlatformInventoryApiTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private const string Path = "/api/v1/platform/organizations";
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable database owner connection required.");
    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted municipal runtime connection required.");
    private static string Platform => Environment.GetEnvironmentVariable("TEST_PLATFORM_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted platform-read connection required.");

    private static async Task<(string Subject, Guid OperatorId)> OperatorAsync()
    {
        var subject = "inventory-" + Guid.NewGuid().ToString("N");
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.platform_operators (identity_issuer, subject, is_active)
            VALUES (@issuer, @sub, TRUE)
            RETURNING operator_id
            """, db);
        command.Parameters.AddWithValue("issuer", OidcApiFactory.Issuer);
        command.Parameters.AddWithValue("sub", subject);
        var id = (Guid)(await command.ExecuteScalarAsync())!;
        return (subject, id);
    }

    private static async Task<Guid> MunicipalityAsync(bool suspended, bool protocol)
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id, name, is_suspended)
                VALUES (@id, 'Comune inventario sintetico', @suspended);
            INSERT INTO platform.organization_modules(organization_id, module_key, enabled)
                VALUES (@id, 'protocol', @protocol);
            """, db);
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("suspended", suspended);
        insert.Parameters.AddWithValue("protocol", protocol);
        await insert.ExecuteNonQueryAsync();
        return id;
    }

    private static async Task<long> AuditCountAsync(Guid operatorId)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.platform_operator_audit_events
            WHERE resource_id = @id AND action = 'platform.organizations.listed'
            """, db);
        command.Parameters.AddWithValue("id", operatorId);
        return (long)(await command.ExecuteScalarAsync())!;
    }

    [Fact]
    public async Task Oidc_platform_operator_can_page_safely_over_minimized_metadata_and_audit_each_read()
    {
        var active = await MunicipalityAsync(false, true);
        var suspended = await MunicipalityAsync(true, false);
        var (subject, operatorId) = await OperatorAsync();
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        var all = new List<(Guid Id, bool Suspended, bool Protocol)>();
        string? after = null;
        var pages = 0;

        do
        {
            var url = Path + "?limit=1" + (after is null ? "" : "&after=" + after);
            using var response = await client.GetAsync(url);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? "");
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = json.RootElement;
            Assert.Equal(2, root.EnumerateObject().Count());
            var organizations = root.GetProperty("organizations");
            Assert.Single(organizations.EnumerateArray());
            var row = organizations[0];
            Assert.Equal(4, row.EnumerateObject().Count());
            all.Add((row.GetProperty("id").GetGuid(), row.GetProperty("isSuspended").GetBoolean(),
                row.GetProperty("protocolEnabled").GetBoolean()));
            Assert.True(row.GetProperty("name").GetString()!.Length is > 0 and <= 200);
            Assert.DoesNotContain(subject, root.ToString());
            Assert.DoesNotContain("identityIssuer", root.ToString());
            Assert.DoesNotContain("membership", root.ToString(), StringComparison.OrdinalIgnoreCase);
            var cursor = root.GetProperty("nextCursor");
            after = cursor.ValueKind == JsonValueKind.Null ? null : cursor.GetString();
            pages++;
            Assert.True(pages < 100, "Keyset pagination must terminate.");
        } while (after is not null);

        Assert.Equal(all.Count, all.Select(x => x.Id).Distinct().Count());
        Assert.Equal(all.Select(x => x.Id).Order(), all.Select(x => x.Id));
        Assert.Contains(all, x => x.Id == active && !x.Suspended && x.Protocol);
        Assert.Contains(all, x => x.Id == suspended && x.Suspended && !x.Protocol);
        Assert.Equal(pages, await AuditCountAsync(operatorId));
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var check = new NpgsqlCommand("""
            SELECT actor_subject, resource_type, correlation_id
            FROM platform.platform_operator_audit_events
            WHERE resource_id = @id AND action = 'platform.organizations.listed'
            """, db);
        check.Parameters.AddWithValue("id", operatorId);
        await using var rows = await check.ExecuteReaderAsync();
        while (await rows.ReadAsync())
        {
            Assert.Equal("platform-operator", rows.GetString(0));
            Assert.Equal("platform.organization-inventory", rows.GetString(1));
            Assert.StartsWith("inventory:", rows.GetString(2));
            Assert.DoesNotContain(subject, rows.GetString(2));
        }
    }

    [Fact]
    public async Task JWT_without_verified_platform_operator_cannot_enumerate_any_organizations()
    {
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Path)).StatusCode);
        using var municipal = factory.Authenticated(factory.Token(subject: "oidc-admin", assertedRole: "Superadmin"));
        Assert.Equal(HttpStatusCode.Forbidden, (await municipal.GetAsync(Path)).StatusCode);
        using var forged = factory.Authenticated(factory.Token(
            subject: "no-platform-operator", organizationId: "", assertedRole: "Superadmin"));
        Assert.Equal(HttpStatusCode.Forbidden, (await forged.GetAsync(Path)).StatusCode);
        using var expired = factory.Authenticated(factory.Token(organizationId: "", expired: true));
        Assert.Equal(HttpStatusCode.Unauthorized, (await expired.GetAsync(Path)).StatusCode);
        using var wrongIssuer = factory.Authenticated(factory.Token(
            issuer: "https://untrusted.example.test/", organizationId: ""));
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrongIssuer.GetAsync(Path)).StatusCode);
        using var wrongAudience = factory.Authenticated(factory.Token(
            audience: "Other.Api", organizationId: ""));
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrongAudience.GetAsync(Path)).StatusCode);
    }

    [Fact]
    public async Task Bad_pagination_or_tenant_override_is_rejected_without_creating_an_audit()
    {
        var (subject, id) = await OperatorAsync();
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        foreach (var query in new[]
        {
            "?limit=0", "?limit=26", "?limit=-1", "?limit=999999",
            "?limit=broken", "?limit=1&after=not-a-guid",
            "?limit=1&after=00000000-0000-0000-0000-000000000000",
            "?limit=1&after=%27%3B%20DROP%20TABLE%20platform.organizations%3B--",
            "?organizationId=11111111-1111-1111-1111-111111111111",
            "?subject=someone-else", "?after=not-a-guid&limit=5"
        })
        {
            using var res = await client.GetAsync(Path + query);
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        }
        Assert.Equal(0, await AuditCountAsync(id));
    }

    [Fact]
    public async Task Platform_operator_revocation_is_checked_again_on_next_inventory_request()
    {
        var (subject, id) = await OperatorAsync();
        using var client = factory.Authenticated(factory.Token(subject: subject, organizationId: ""));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(Path + "?limit=2")).StatusCode);
        Assert.Equal(1, await AuditCountAsync(id));
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using (var revoke = new NpgsqlCommand("""
            UPDATE platform.platform_operators SET is_active = FALSE
            WHERE identity_issuer = @issuer AND subject = @subject
            """, db))
        {
            revoke.Parameters.AddWithValue("issuer", OidcApiFactory.Issuer);
            revoke.Parameters.AddWithValue("subject", subject);
            await revoke.ExecuteNonQueryAsync();
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(Path)).StatusCode);
        Assert.Equal(1, await AuditCountAsync(id));
    }

    [Fact]
    public async Task Sql_logins_have_disjoint_access_to_global_inventory_and_tenant_tables()
    {
        await using var runtime = new NpgsqlConnection(Runtime);
        await runtime.OpenAsync();
        await using (var query = new NpgsqlCommand("""
            SELECT has_table_privilege(current_user,
                'platform.platform_organization_inventory', 'SELECT'),
              has_function_privilege(current_user,
                'platform.active_platform_operator_id(text,text)', 'EXECUTE')
            """, runtime))
        {
            await using var row = await query.ExecuteReaderAsync();
            Assert.True(await row.ReadAsync());
            Assert.False(row.GetBoolean(0));
            Assert.False(row.GetBoolean(1));
        }
        await using (var deny = new NpgsqlCommand(
            "SELECT id FROM platform.platform_organization_inventory LIMIT 1", runtime))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => deny.ExecuteScalarAsync());
            Assert.Equal("42501", error.SqlState);
        }

        await using var platform = new NpgsqlConnection(Platform);
        await platform.OpenAsync();
        await using var probe = new NpgsqlCommand("""
            SELECT
              has_table_privilege(current_user, 'platform.platform_organization_inventory', 'SELECT'),
              has_table_privilege(current_user, 'platform.organizations', 'SELECT'),
              has_table_privilege(current_user, 'platform.organization_modules', 'SELECT'),
              has_table_privilege(current_user, 'platform.organization_memberships', 'SELECT'),
              has_table_privilege(current_user, 'protocol.records', 'SELECT'),
              has_table_privilege(current_user, 'platform.platform_operators', 'SELECT'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'INSERT'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'SELECT'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'UPDATE'),
              has_table_privilege(current_user, 'platform.platform_operator_audit_events', 'DELETE'),
              has_function_privilege(current_user,
                'platform.active_platform_operator_id(text,text)', 'EXECUTE')
            """, platform);
        await using (var row = await probe.ExecuteReaderAsync())
        {
            Assert.True(await row.ReadAsync());
            Assert.True(row.GetBoolean(0));
            for (var i = 1; i <= 5; i++) Assert.False(row.GetBoolean(i));
            Assert.True(row.GetBoolean(6));
            for (var i = 7; i <= 9; i++) Assert.False(row.GetBoolean(i));
            Assert.True(row.GetBoolean(10));
        }
        await using (var deny = new NpgsqlCommand(
            "SELECT subject FROM platform.organization_memberships LIMIT 1", platform))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => deny.ExecuteScalarAsync());
            Assert.Equal("42501", error.SqlState);
        }
        await using (var query = new NpgsqlCommand("""
            SELECT id, name, is_suspended, protocol_enabled
            FROM platform.platform_organization_inventory ORDER BY id LIMIT 2
            """, platform))
        {
            await using var reader = await query.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
        }
    }
}

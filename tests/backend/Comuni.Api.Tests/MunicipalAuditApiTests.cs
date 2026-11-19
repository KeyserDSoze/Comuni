using System.Net;
using System.Text.Json;
using Comuni.Domains.Audit;
using Comuni.Infrastructures.Persistence;
using Comuni.Business.Organizations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>Admin's own tenant audit summary. Real PostgreSQL, not EF in-memory.</summary>
public sealed class MunicipalAuditApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string Endpoint = "/api/v1/admin/audit";

    private async Task<Guid> SeedAsync(int events)
    {
        var organization = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organizations (id,name) VALUES ({organization}, {"Comune audit sintetico"})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_modules (organization_id,module_key,enabled) VALUES ({organization}, {"protocol"}, {true})");
        foreach (var membership in new[] { ("audit-admin", "Admin"), ("audit-reader", "Reader"), ("audit-officer", "Officer") })
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO platform.organization_memberships(organization_id,subject,role,is_active) VALUES ({organization}, {membership.Item1}, {membership.Item2}, {true})");
        for (var i = 0; i < events; ++i)
        {
            var id = Guid.NewGuid();
            var occurred = new DateTimeOffset(2026, 11, 16, 9, 0, 0, TimeSpan.Zero).AddMinutes(i);
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO platform.audit_events
                    (id, organization_id, actor_subject, action, resource_type,
                     resource_id, correlation_id, occurred_at)
                VALUES ({id}, {organization}, {"hidden-actor-identifiable"},
                    {"platform.module.protocol.enabled"}, {"platform.module"},
                    {organization}, {"hidden-correlation-identifiable"}, {occurred})
                """);
        }
        return organization;
    }

    [Fact]
    public async Task Admin_reads_only_25_recent_minimal_events_from_own_municipality()
    {
        var own = await SeedAsync(30);
        var other = await SeedAsync(3);
        using var client = factory.ClientFor(own.ToString(), "Admin", "audit-admin");
        using var response = await client.GetAsync(Endpoint);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? "");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var events = json.RootElement.EnumerateArray().ToArray();
        Assert.Equal(25, events.Length);
        foreach (var item in events)
        {
            Assert.Equal(4, item.EnumerateObject().Count());
            Assert.True(item.TryGetProperty("id", out _));
            Assert.Equal("platform.module.protocol.enabled", item.GetProperty("action").GetString());
            Assert.Equal("platform.module", item.GetProperty("resourceType").GetString());
            Assert.True(item.GetProperty("occurredAt").GetDateTimeOffset() > DateTimeOffset.MinValue);
        }
        var ordered = events.Select(x => x.GetProperty("occurredAt").GetDateTimeOffset()).ToArray();
        Assert.Equal(ordered.OrderByDescending(x => x), ordered);
        var body = json.RootElement.ToString();
        Assert.DoesNotContain(own.ToString(), body);
        Assert.DoesNotContain(other.ToString(), body);
        Assert.DoesNotContain("hidden-actor-identifiable", body);
        Assert.DoesNotContain("hidden-correlation-identifiable", body);
        Assert.DoesNotContain("organizationId", body);
        Assert.DoesNotContain("resourceId", body);
        Assert.DoesNotContain("actorSubject", body);
        Assert.DoesNotContain("correlationId", body);
    }

    [Fact]
    public async Task Anonymous_reader_officer_claim_forgery_and_foreign_tenant_are_denied()
    {
        var a = await SeedAsync(1);
        var b = await SeedAsync(1);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Endpoint)).StatusCode);
        foreach (var role in new[] { "Reader", "Officer" })
        {
            using var user = factory.ClientFor(a.ToString(), role, "audit-" + role.ToLowerInvariant());
            Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync(Endpoint)).StatusCode);
        }
        using var forged = factory.ClientFor(a.ToString(), "Admin", "audit-reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await forged.GetAsync(Endpoint)).StatusCode);
        using var cross = factory.ClientFor(b.ToString(), "Admin", "audit-admin");
        using var response = await cross.GetAsync(Endpoint);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Single(json.RootElement.EnumerateArray());

        await using var owner = new NpgsqlConnection(
            Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")!);
        await owner.OpenAsync();
        await using var suspend = new NpgsqlCommand(
            "UPDATE platform.organizations SET is_suspended=TRUE WHERE id=@id", owner);
        suspend.Parameters.AddWithValue("id", a);
        await suspend.ExecuteNonQueryAsync();
        using var suspended = factory.ClientFor(a.ToString(), "Admin", "audit-admin");
        Assert.Equal(HttpStatusCode.Forbidden, (await suspended.GetAsync(Endpoint)).StatusCode);
    }

    [Fact]
    public async Task No_client_provided_tenant_or_unbounded_query_is_accepted()
    {
        var organization = await SeedAsync(2);
        using var client = factory.ClientFor(organization.ToString(), "Admin", "audit-admin");
        foreach (var query in new[]
        {
            "?limit=1000000", "?after=2026-11-16", "?organizationId=" + Guid.NewGuid(),
            "?actor=anything", "?limit=5&limit=6", "?action=platform.module.protocol.enabled"
        })
        {
            var response = await client.GetAsync(Endpoint + query);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Runtime_can_only_select_safe_audit_columns_and_cannot_read_other_tenants_without_signed_proof()
    {
        var own = await SeedAsync(2);
        await SeedAsync(1);
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")!;
        await using var db = new NpgsqlConnection(runtime);
        await db.OpenAsync();
        await using (var permissions = new NpgsqlCommand("""
            SELECT has_column_privilege(current_user, 'platform.audit_events', 'id', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'organization_id', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'action', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'resource_type', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'occurred_at', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'actor_subject', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'resource_id', 'SELECT'),
                   has_column_privilege(current_user, 'platform.audit_events', 'correlation_id', 'SELECT'),
                   has_table_privilege(current_user, 'platform.audit_events', 'UPDATE'),
                   has_table_privilege(current_user, 'platform.audit_events', 'DELETE')
            """, db))
        await using (var rows = await permissions.ExecuteReaderAsync())
        {
            Assert.True(await rows.ReadAsync());
            for (var i = 0; i < 5; i++) Assert.True(rows.GetBoolean(i));
            for (var i = 5; i < 10; i++) Assert.False(rows.GetBoolean(i));
        }

        await using (var forbidden = new NpgsqlCommand(
            "SELECT actor_subject FROM platform.audit_events", db))
        {
            var ex = await Assert.ThrowsAsync<PostgresException>(() => forbidden.ExecuteScalarAsync());
            Assert.Equal("42501", ex.SqlState);
        }

        await using var transaction = await db.BeginTransactionAsync();
        await using (var unsigned = new NpgsqlCommand(
            "SELECT set_config('comuni.organization_id', @id, true)", db, transaction))
        {
            unsigned.Parameters.AddWithValue("id", own.ToString());
            await unsigned.ExecuteScalarAsync();
        }
        await using var probe = new NpgsqlCommand(
            "SELECT count(id) FROM platform.audit_events", db, transaction);
        Assert.Equal(0L, (long)(await probe.ExecuteScalarAsync())!);
        await transaction.RollbackAsync();

        // Positive path MUST use the restricted runtime SQL login, not the
        // schema-owner used for fixtures. A signed tenant proof exposes only
        // the events of the organization actually selected by the API.
        var key = Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Signed RLS proof key required.");
        var signer = new TenantProofSigner(key);
        var opts = new DbContextOptionsBuilder<ComuniDbContext>()
            .UseNpgsql(runtime).Options;

        await using (var ownDb = new ComuniDbContext(opts, new TestOrganization(own)))
        {
            await using var signed = await TenantDatabaseTransaction.BeginAsync(
                ownDb, signer, CancellationToken.None);
            var consultation = AuditEvent.Create(own, "synthetic-runtime-admin",
                "platform.audit.consulted", "platform.audit", own, "synthetic-probe-audit");
            var reader = new OrganizationAuditReader(ownDb);
            var listed = await reader.ListRecentAndRecordAsync(
                own, consultation, CancellationToken.None);
            Assert.Equal(2, listed.Count);
            Assert.All(listed, item => Assert.Equal("platform.module.protocol.enabled", item.Action));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                reader.ListRecentAndRecordAsync(Guid.NewGuid(), consultation, CancellationToken.None));
        }

        var second = await SeedAsync(1);
        await using (var otherDb = new ComuniDbContext(opts, new TestOrganization(second)))
        {
            await using var signed = await TenantDatabaseTransaction.BeginAsync(
                otherDb, signer, CancellationToken.None);
            var consultation = AuditEvent.Create(second, "synthetic-runtime-admin",
                "platform.audit.consulted", "platform.audit", second, "other-synthetic-probe-audit");
            var listed = await new OrganizationAuditReader(otherDb)
                .ListRecentAndRecordAsync(second, consultation, CancellationToken.None);
            Assert.Single(listed);
        }
    }

    private sealed class TestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }
}

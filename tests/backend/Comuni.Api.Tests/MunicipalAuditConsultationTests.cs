using System.Net;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Consultations of the municipal audit are themselves sensitive. All tests
/// exercise the real ASP.NET Core authorization pipeline and PostgreSQL.
/// </summary>
public sealed class MunicipalAuditConsultationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string Endpoint = "/api/v1/admin/audit";
    private const string Action = "platform.audit.consulted";

    private async Task<Guid> SeedAsync(bool suspended = false)
    {
        var id = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organizations(id,name,is_suspended) VALUES ({id}, {"Comune audit synthetic"}, {suspended})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_memberships(organization_id,subject,role,is_active) VALUES ({id}, {"audit-admin"}, {"Admin"}, {true}), ({id}, {"audit-reader"}, {"Reader"}, {true}), ({id}, {"audit-officer"}, {"Officer"}, {true})");
        var oldId = Guid.NewGuid();
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO platform.audit_events(id,organization_id,actor_subject,action,resource_type,resource_id,correlation_id,occurred_at)
            VALUES ({oldId}, {id}, {"old-actor"}, {"platform.module.protocol.enabled"}, {"platform.module"}, {id}, {"old-request"}, {DateTimeOffset.UtcNow.AddDays(-2)})
            """);
        return id;
    }

    private static async Task<(Guid Id, Guid Organization, string Actor, string Correlation, Guid Resource, string Type)[]>
        ReadConsultationsAsync(Guid id)
    {
        await using var db = new NpgsqlConnection(Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")!);
        await db.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT id, organization_id, actor_subject, correlation_id, resource_id, resource_type
            FROM platform.audit_events
            WHERE organization_id = @id AND action = 'platform.audit.consulted'
            ORDER BY occurred_at, id
            """, db);
        query.Parameters.AddWithValue("id", id);
        var result = new List<(Guid, Guid, string, string, Guid, string)>();
        await using var rows = await query.ExecuteReaderAsync();
        while (await rows.ReadAsync())
            result.Add((rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2),
                        rows.GetString(3), rows.GetGuid(4), rows.GetString(5)));
        return result.ToArray();
    }

    [Fact]
    public async Task Each_successful_Admin_read_has_one_trusted_audit_event_and_does_not_log_itself()
    {
        var id = await SeedAsync();
        using var admin = factory.ClientFor(id.ToString(), "Admin", "audit-admin");
        admin.DefaultRequestHeaders.TryAddWithoutValidation("X-Actor-Subject", "forged");
        admin.DefaultRequestHeaders.TryAddWithoutValidation("X-Correlation-Id", "forged");

        using var first = await admin.GetAsync(Endpoint);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var firstJson = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        Assert.Single(firstJson.RootElement.EnumerateArray());
        Assert.Equal("platform.module.protocol.enabled",
            firstJson.RootElement[0].GetProperty("action").GetString());

        var firstEvents = await ReadConsultationsAsync(id);
        var logged = Assert.Single(firstEvents);
        Assert.Equal(id, logged.Organization);
        Assert.Equal(id, logged.Resource);
        Assert.Equal("platform.audit", logged.Type);
        Assert.Equal("audit-admin", logged.Actor);
        Assert.NotEqual("forged", logged.Correlation);
        Assert.NotEqual(string.Empty, logged.Correlation);

        using var second = await admin.GetAsync(Endpoint);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        using var secondJson = JsonDocument.Parse(await second.Content.ReadAsStringAsync());
        Assert.Contains(secondJson.RootElement.EnumerateArray(),
            item => item.GetProperty("action").GetString() == Action);
        Assert.Equal(2, (await ReadConsultationsAsync(id)).Length);

        var response = secondJson.RootElement.ToString();
        Assert.DoesNotContain("audit-admin", response);
        Assert.DoesNotContain("forged", response);
        Assert.DoesNotContain("actorSubject", response);
        Assert.DoesNotContain("correlationId", response);
        Assert.DoesNotContain("resourceId", response);
        Assert.DoesNotContain("organizationId", response);
    }

    [Fact]
    public async Task Denied_or_invalid_requests_do_not_append_consultation_events()
    {
        var active = await SeedAsync();
        var suspended = await SeedAsync(true);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Endpoint)).StatusCode);

        foreach (var role in new[] { "Reader", "Officer" })
        {
            using var denied = factory.ClientFor(active.ToString(), role, "audit-" + role.ToLowerInvariant());
            Assert.Equal(HttpStatusCode.Forbidden, (await denied.GetAsync(Endpoint)).StatusCode);
        }
        using (var forged = factory.ClientFor(active.ToString(), "Admin", "audit-reader"))
            Assert.Equal(HttpStatusCode.Forbidden, (await forged.GetAsync(Endpoint)).StatusCode);
        using (var blocked = factory.ClientFor(suspended.ToString(), "Admin", "audit-admin"))
            Assert.Equal(HttpStatusCode.Forbidden, (await blocked.GetAsync(Endpoint)).StatusCode);
        using (var admin = factory.ClientFor(active.ToString(), "Admin", "audit-admin"))
        {
            Assert.Equal(HttpStatusCode.BadRequest,
                (await admin.GetAsync(Endpoint + "?organizationId=" + suspended)).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest,
                (await admin.GetAsync(Endpoint + "?limit=10000")).StatusCode);
        }

        Assert.Empty(await ReadConsultationsAsync(active));
        Assert.Empty(await ReadConsultationsAsync(suspended));
    }

    [Fact]
    public async Task Restricted_runtime_requires_signed_transaction_and_records_only_on_commit()
    {
        var id = await SeedAsync();
        var connection = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted runtime connection is required.");
        var signingKey = Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Test-only signed RLS key is required.");
        var signer = new TenantProofSigner(signingKey);
        var options = new DbContextOptionsBuilder<ComuniDbContext>()
            .UseNpgsql(connection).Options;

        var audit = AuditEvent.Create(id, "signed-runtime-admin", Action,
            "platform.audit", id, "server-correlation");

        // The repository must never start an unsigned, autonomous read/append
        // outside the existing SQL proof transaction.
        await using (var outside = new ComuniDbContext(options, new TestOrganization(id)))
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new OrganizationAuditReader(outside).ListRecentAndRecordAsync(
                    id, audit, CancellationToken.None));

        await using (var db = new ComuniDbContext(options, new TestOrganization(id)))
        {
            await using var tx = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                new OrganizationAuditReader(db).ListRecentAndRecordAsync(
                    Guid.NewGuid(), audit, CancellationToken.None));
            var result = await new OrganizationAuditReader(db)
                .ListRecentAndRecordAsync(id, audit, CancellationToken.None);
            Assert.Single(result);
            Assert.Equal("platform.module.protocol.enabled", result[0].Action);
            await tx.RollbackAsync();
        }
        Assert.Empty(await ReadConsultationsAsync(id));

        var newAudit = AuditEvent.Create(id, "signed-runtime-admin", Action,
            "platform.audit", id, "second-server-correlation");
        await using (var db = new ComuniDbContext(options, new TestOrganization(id)))
        {
            await using var tx = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            Assert.Single(await new OrganizationAuditReader(db)
                .ListRecentAndRecordAsync(id, newAudit, CancellationToken.None));
            await tx.CommitAsync();
        }

        var committed = Assert.Single(await ReadConsultationsAsync(id));
        Assert.Equal("signed-runtime-admin", committed.Actor);
        Assert.Equal("second-server-correlation", committed.Correlation);
        Assert.Equal(id, committed.Organization);
        Assert.Equal(id, committed.Resource);
    }

    private sealed class TestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }

    [Fact]
    public async Task Different_organizations_never_share_consultation_events()
    {
        var a = await SeedAsync();
        var b = await SeedAsync();
        using var adminA = factory.ClientFor(a.ToString(), "Admin", "audit-admin");
        using var adminB = factory.ClientFor(b.ToString(), "Admin", "audit-admin");

        Assert.Equal(HttpStatusCode.OK, (await adminA.GetAsync(Endpoint)).StatusCode);
        Assert.Single(await ReadConsultationsAsync(a));
        Assert.Empty(await ReadConsultationsAsync(b));

        Assert.Equal(HttpStatusCode.OK, (await adminB.GetAsync(Endpoint)).StatusCode);
        var aRows = await ReadConsultationsAsync(a);
        var bRows = await ReadConsultationsAsync(b);
        Assert.Single(aRows);
        Assert.Single(bRows);
        Assert.NotEqual(aRows[0].Id, bRows[0].Id);
    }
}

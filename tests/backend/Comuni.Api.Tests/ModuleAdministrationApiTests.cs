using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>Unique organizations for each test avoid cross-test state pollution.</summary>
public sealed class ModuleAdministrationApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private async Task<string> SeedOrganizationAsync(bool enabled = true)
    {
        var id = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organizations (id, name) VALUES ({id}, {"Comune di prova"})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES ({id}, {"protocol"}, {enabled})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES ({id}, {"test-admin"}, {"Admin"}, {true}), ({id}, {"test-reader"}, {"Reader"}, {true}), ({id}, {"test-officer"}, {"Officer"}, {true})");
        return id.ToString();
    }

    [Fact]
    public async Task Anonymous_cannot_access_administration()
    {
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/admin/modules")).StatusCode);
    }

    [Theory]
    [InlineData("Reader")]
    [InlineData("Officer")]
    public async Task Non_admin_memberships_cannot_read_or_change_flags(string role)
    {
        var org = await SeedOrganizationAsync();
        using var client = factory.ClientFor(org, role);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { enabled = false })).StatusCode);
    }

    [Fact]
    public async Task JWT_admin_claim_does_not_override_Reader_membership()
    {
        var org = await SeedOrganizationAsync();
        using var client = factory.ClientFor(org, "Admin", "test-reader");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { enabled = false })).StatusCode);
    }

    [Fact]
    public async Task Admin_can_disable_and_reenable_protocol_backend_immediately()
    {
        var org = await SeedOrganizationAsync();
        using var client = factory.ClientFor(org, "Admin");
        using var list = JsonDocument.Parse(await client.GetStringAsync("/api/v1/admin/modules"));
        Assert.Contains(list.RootElement.EnumerateArray(),
            item => item.GetProperty("key").GetString() == "protocol" && item.GetProperty("enabled").GetBoolean());

        Assert.Equal(HttpStatusCode.OK,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { enabled = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
        using var context = JsonDocument.Parse(await client.GetStringAsync("/api/v1/context"));
        Assert.DoesNotContain(context.RootElement.GetProperty("modules").EnumerateArray(),
            item => item.GetString() == "protocol");

        Assert.Equal(HttpStatusCode.OK,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
    }

    [Fact]
    public async Task Body_cannot_select_a_different_organization()
    {
        var first = await SeedOrganizationAsync();
        var second = await SeedOrganizationAsync();
        using var client = factory.ClientFor(first, "Admin");
        Assert.Equal(HttpStatusCode.OK,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol",
                new { enabled = false, organizationId = second })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var flags = await db.OrganizationModules.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.OrganizationId == Guid.Parse(first) || x.OrganizationId == Guid.Parse(second))
            .ToDictionaryAsync(x => x.OrganizationId, x => x.Enabled);
        Assert.False(flags[Guid.Parse(first)]);
        Assert.True(flags[Guid.Parse(second)]);
    }

    [Fact]
    public async Task Changing_flag_produces_one_server_originated_audit_but_no_op_does_not()
    {
        var org = await SeedOrganizationAsync();
        using var client = factory.ClientFor(org, "Admin");
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-Actor-Subject", "forged");
        var result = await client.PutAsJsonAsync("/api/v1/admin/modules/protocol",
            new { enabled = false, actorSubject = "forged" });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { enabled = false })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var audits = await db.AuditEvents.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.OrganizationId == Guid.Parse(org) && x.Action == "platform.module.protocol.disabled")
            .ToArrayAsync();
        var audit = Assert.Single(audits);
        Assert.Equal("test-admin", audit.ActorSubject);
        Assert.Equal(Guid.Parse(org), audit.ResourceId);
        Assert.Equal("platform.module", audit.ResourceType);
        Assert.NotEqual("forged", audit.CorrelationId);
    }

    [Fact]
    public async Task Unknown_module_is_not_created_and_missing_enabled_is_invalid()
    {
        var org = await SeedOrganizationAsync();
        using var client = factory.ClientFor(org, "Admin");
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/unknown", new { enabled = false })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await client.PutAsJsonAsync("/api/v1/admin/modules/protocol", new { wrong = true })).StatusCode);
    }
}

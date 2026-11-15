using System.Net;
using System.Net.Http.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class SuspendedOrganizationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Suspended_organization_cannot_read_context_or_protocol_or_write_audit()
    {
        var id = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO platform.organizations (id, name) VALUES ({id}, {"Comune sospeso"});
                INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
                    VALUES ({id}, {"protocol"}, TRUE);
                INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active)
                    VALUES ({id}, {"test-admin"}, {"Admin"}, TRUE);
                """);
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE platform.organizations SET is_suspended = TRUE WHERE id = {id}");
        }

        using var suspended = factory.ClientFor(id.ToString(), "Admin");
        Assert.Equal(HttpStatusCode.Forbidden, (await suspended.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await suspended.GetAsync("/api/v1/protocol/records")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await suspended.PostAsJsonAsync("/api/v1/protocol/records", new { subject = "Non registrare" })).StatusCode);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
            Assert.False(await db.ProtocolRecords.IgnoreQueryFilters().AnyAsync(r => r.OrganizationId == id));
            Assert.False(await db.AuditEvents.IgnoreQueryFilters().AnyAsync(r => r.OrganizationId == id));
        }

        using var active = factory.ClientFor(ApiFactory.OrgA, "Reader");
        Assert.Equal(HttpStatusCode.OK, (await active.GetAsync("/api/v1/context")).StatusCode);
    }
}
